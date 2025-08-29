//go:build windows

package win_rdp

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinRDP represents the Windows RDP collection module.
type WinRDP struct{}

// NewWinRDP creates a new Windows RDP collection module.
func NewWinRDP() *WinRDP {
	return &WinRDP{}
}

// Name returns the module's identifier.
func (w *WinRDP) Name() string {
	return "windows/rdp"
}

// Collect copies Windows RDP artifacts including bitmap cache and configuration.
func (w *WinRDP) Collect(ctx context.Context, outDir string) error {
	// Create the windows/rdp subdirectory
	rdpDir := filepath.Join(outDir, "windows", "rdp")
	if err := winutil.EnsureDir(rdpDir); err != nil {
		return fmt.Errorf("failed to create rdp directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewRDPManifest(hostname)

	// Initialize size constraints
	constraints := winutil.NewSizeConstraints()

	// Enumerate user profiles for per-user RDP artifacts
	if err := w.collectPerUserRDPArtifacts(ctx, rdpDir, manifest, constraints); err != nil {
		manifest.AddError("user_artifacts", fmt.Sprintf("Failed to collect per-user RDP artifacts: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(rdpDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectPerUserRDPArtifacts collects RDP artifacts for each user profile.
func (w *WinRDP) collectPerUserRDPArtifacts(ctx context.Context, outDir string, manifest *RDPManifest, constraints *winutil.SizeConstraints) error {
	// Get system drive (usually C:)
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	usersDir := filepath.Join(systemDrive, "Users")
	userEntries, err := os.ReadDir(usersDir)
	if err != nil {
		return fmt.Errorf("failed to read users directory: %w", err)
	}

	for _, userEntry := range userEntries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !userEntry.IsDir() {
			continue
		}

		username := userEntry.Name()
		
		// Skip system profiles
		if w.isSystemProfile(username) {
			continue
		}

		userProfileDir := filepath.Join(usersDir, username)
		
		// Create user-specific output directory
		userOutDir := filepath.Join(outDir, "users", username)
		if err := winutil.EnsureDir(userOutDir); err != nil {
			manifest.AddError(userProfileDir, fmt.Sprintf("Failed to create user output directory: %v", err))
			continue
		}

		// Collect RDP bitmap cache
		if err := w.collectRDPBitmapCache(ctx, userProfileDir, userOutDir, manifest, constraints, username); err != nil {
			manifest.AddError(userProfileDir, fmt.Sprintf("Failed to collect RDP bitmap cache: %v", err))
		}

		// Collect Default.rdp if present
		if err := w.collectDefaultRDP(ctx, userProfileDir, userOutDir, manifest, username); err != nil {
			manifest.AddError(userProfileDir, fmt.Sprintf("Failed to collect Default.rdp: %v", err))
		}
	}

	return nil
}

// collectRDPBitmapCache collects RDP bitmap cache files for a user.
func (w *WinRDP) collectRDPBitmapCache(ctx context.Context, userProfileDir, userOutDir string, manifest *RDPManifest, constraints *winutil.SizeConstraints, username string) error {
	// RDP bitmap cache is typically at %LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\
	cacheDir := filepath.Join(userProfileDir, "AppData", "Local", "Microsoft", "Terminal Server Client", "Cache")
	
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		// Cache directory might not exist if user hasn't used RDP
		return nil
	}

	// Create cache output directory
	cacheOutDir := filepath.Join(userOutDir, "bitmap_cache")
	if err := winutil.EnsureDir(cacheOutDir); err != nil {
		return fmt.Errorf("failed to create cache output directory: %w", err)
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		manifest.IncrementTotalFiles()

		srcPath := filepath.Join(cacheDir, filename)
		destPath := filepath.Join(cacheOutDir, filename)

		// Get file info
		stat, err := os.Stat(srcPath)
		if err != nil {
			manifest.AddError(srcPath, fmt.Sprintf("Failed to stat file: %v", err))
			continue
		}

		// Use smart copy with size constraints
		size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints)
		if err != nil {
			manifest.AddError(srcPath, fmt.Sprintf("Failed to copy file: %v", err))
			continue
		}

		// Generate relative path for manifest
		relPath := filepath.Join("users", username, "bitmap_cache", filename)
		note := fmt.Sprintf("RDP bitmap cache file for user %s (%s)", username, filename)

		// Add to manifest
		manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "bitmap_cache", note)
	}

	return nil
}

// collectDefaultRDP collects Default.rdp configuration file for a user.
func (w *WinRDP) collectDefaultRDP(ctx context.Context, userProfileDir, userOutDir string, manifest *RDPManifest, username string) error {
	defaultRDPPath := filepath.Join(userProfileDir, "Default.rdp")
	
	// Check if Default.rdp exists
	stat, err := os.Stat(defaultRDPPath)
	if err != nil {
		// File doesn't exist, which is normal
		return nil
	}

	manifest.IncrementTotalFiles()

	destPath := filepath.Join(userOutDir, "Default.rdp")

	// Copy the file
	srcFile, err := winutil.OpenForCopy(defaultRDPPath)
	if err != nil {
		return fmt.Errorf("failed to open Default.rdp: %w", err)
	}
	defer srcFile.Close()

	size, sha256Hex, err := winutil.CopyFileStreaming(srcFile, destPath)
	if err != nil {
		return fmt.Errorf("failed to copy Default.rdp: %w", err)
	}

	// Generate relative path for manifest
	relPath := filepath.Join("users", username, "Default.rdp")
	note := fmt.Sprintf("RDP configuration file for user %s", username)

	// Add to manifest
	manifest.AddItem(relPath, size, sha256Hex, false, stat.ModTime(), "config", note)

	return nil
}

// isSystemProfile checks if a username represents a system profile that should be skipped.
func (w *WinRDP) isSystemProfile(username string) bool {
	systemProfiles := []string{
		"All Users", "Default", "Default User", "Public", 
		"WDAGUtilityAccount", "defaultuser0", "systemprofile",
	}
	
	lowerUsername := strings.ToLower(username)
	for _, profile := range systemProfiles {
		if lowerUsername == strings.ToLower(profile) {
			return true
		}
	}
	
	return false
}