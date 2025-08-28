//go:build windows

package win_lnk

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinLNK represents the Windows shortcut files collection module.
type WinLNK struct{}

// NewWinLNK creates a new Windows shortcut files collection module.
func NewWinLNK() *WinLNK {
	return &WinLNK{}
}

// Name returns the module's identifier.
func (w *WinLNK) Name() string {
	return "windows/lnk"
}

// Collect copies Windows shortcut files and creates a manifest.
func (w *WinLNK) Collect(ctx context.Context, outDir string) error {
	// Create the windows/lnk subdirectory
	lnkDir := filepath.Join(outDir, "windows", "lnk")
	if err := winutil.EnsureDir(lnkDir); err != nil {
		return fmt.Errorf("failed to create lnk directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewLNKManifest(hostname)

	// Initialize size constraints
	constraints := winutil.NewSizeConstraints()

	// Get system drive (usually C:)
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	// Collect LNK files from all user profiles
	usersDir := filepath.Join(systemDrive, "Users")
	if err := w.collectFromUsersDirectory(ctx, usersDir, lnkDir, manifest, constraints); err != nil {
		manifest.AddError("users_directory", fmt.Sprintf("Failed to process users directory: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(lnkDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectFromUsersDirectory iterates through user profiles and collects LNK files.
func (w *WinLNK) collectFromUsersDirectory(ctx context.Context, usersDir, outDir string, manifest *LNKManifest, constraints *winutil.SizeConstraints) error {
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return fmt.Errorf("failed to read users directory: %w", err)
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if !entry.IsDir() {
			continue
		}

		username := entry.Name()
		
		// Skip system profiles and common non-user directories
		if w.shouldSkipUser(username) {
			continue
		}

		manifest.IncrementUsersProcessed()

		// Collect from Recent folder (main target per readme_3.md)
		recentDir := filepath.Join(usersDir, username, "AppData", "Roaming", "Microsoft", "Windows", "Recent")
		w.collectLNKFromDirectory(ctx, recentDir, outDir, "recent", username, manifest, constraints)

		// Optional: Collect from Desktop (with caps)
		desktopDir := filepath.Join(usersDir, username, "Desktop")
		w.collectLNKFromDirectory(ctx, desktopDir, outDir, "desktop", username, manifest, constraints)

		// Optional: Collect from Start Menu (with caps)
		startMenuDir := filepath.Join(usersDir, username, "AppData", "Roaming", "Microsoft", "Windows", "Start Menu")
		w.collectLNKFromDirectory(ctx, startMenuDir, outDir, "startmenu", username, manifest, constraints)
	}

	return nil
}

// collectLNKFromDirectory collects LNK files from a specific directory.
func (w *WinLNK) collectLNKFromDirectory(ctx context.Context, sourceDir, outDir, location, username string, manifest *LNKManifest, constraints *winutil.SizeConstraints) {
	// Walk the directory tree to handle subdirectories (especially for Start Menu)
	err := filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			// Don't treat as error if directory doesn't exist
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			return nil
		}

		filename := d.Name()
		
		// Only collect .lnk files
		if !strings.HasSuffix(strings.ToLower(filename), ".lnk") {
			return nil
		}

		manifest.IncrementTotalFiles()

		// Create destination filename with user and location prefix to avoid collisions
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			relPath = filename
		}
		// Replace path separators with underscores for flat storage
		destFilename := fmt.Sprintf("%s_%s_%s", username, location, strings.ReplaceAll(relPath, string(filepath.Separator), "_"))
		destPath := filepath.Join(outDir, destFilename)

		// Get file info
		stat, err := os.Stat(path)
		if err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to stat file: %v", err))
			return nil
		}

		// Use smart copy with size constraints
		size, sha256Hex, truncated, err := winutil.SmartCopy(path, destPath, constraints)
		if err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to copy file: %v", err))
			return nil
		}

		// Generate description
		note := w.generateFileNote(filename, location, relPath)

		// Add to manifest
		manifest.AddItem(destFilename, size, sha256Hex, truncated, stat.ModTime(), username, location, note)

		return nil
	})

	if err != nil && !os.IsNotExist(err) {
		manifest.AddError(fmt.Sprintf("%s_%s", username, location), fmt.Sprintf("Failed to walk directory: %v", err))
	}
}

// shouldSkipUser determines if a user directory should be skipped.
func (w *WinLNK) shouldSkipUser(username string) bool {
	skipUsers := []string{
		"All Users",
		"Default",
		"Default User", 
		"Public",
		"desktop.ini",
		"WDAGUtilityAccount",
	}

	lowerUsername := strings.ToLower(username)
	for _, skipUser := range skipUsers {
		if lowerUsername == strings.ToLower(skipUser) {
			return true
		}
	}

	// Skip users starting with common system prefixes
	if strings.HasPrefix(lowerUsername, "defaultapp") || 
	   strings.HasPrefix(lowerUsername, "systemprofile") ||
	   strings.HasPrefix(lowerUsername, "localservice") ||
	   strings.HasPrefix(lowerUsername, "networkservice") {
		return true
	}

	return false
}

// generateFileNote creates a descriptive note for LNK files.
func (w *WinLNK) generateFileNote(filename, location, relPath string) string {
	switch location {
	case "recent":
		return fmt.Sprintf("Recent shortcut file (%s)", filename)
	case "desktop":
		return fmt.Sprintf("Desktop shortcut (%s)", relPath)
	case "startmenu":
		return fmt.Sprintf("Start Menu shortcut (%s)", relPath)
	default:
		return fmt.Sprintf("Shortcut file (%s)", filename)
	}
}