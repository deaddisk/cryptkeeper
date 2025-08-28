//go:build windows

package win_jumplists

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinJumpLists represents the Windows jump lists collection module.
type WinJumpLists struct{}

// NewWinJumpLists creates a new Windows jump lists collection module.
func NewWinJumpLists() *WinJumpLists {
	return &WinJumpLists{}
}

// Name returns the module's identifier.
func (w *WinJumpLists) Name() string {
	return "windows/jumplists"
}

// Collect copies Windows jump list files and creates a manifest.
func (w *WinJumpLists) Collect(ctx context.Context, outDir string) error {
	// Create the windows/jumplists subdirectory
	jumplistsDir := filepath.Join(outDir, "windows", "jumplists")
	if err := winutil.EnsureDir(jumplistsDir); err != nil {
		return fmt.Errorf("failed to create jumplists directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewJumpListManifest(hostname)

	// Initialize size constraints
	constraints := winutil.NewSizeConstraints()

	// Get system drive (usually C:)
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	// Collect jump lists from all user profiles
	usersDir := filepath.Join(systemDrive, "Users")
	if err := w.collectFromUsersDirectory(ctx, usersDir, jumplistsDir, manifest, constraints); err != nil {
		manifest.AddError("users_directory", fmt.Sprintf("Failed to process users directory: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(jumplistsDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectFromUsersDirectory iterates through user profiles and collects jump lists.
func (w *WinJumpLists) collectFromUsersDirectory(ctx context.Context, usersDir, outDir string, manifest *JumpListManifest, constraints *winutil.SizeConstraints) error {
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

		// Collect automatic jump lists
		automaticDir := filepath.Join(usersDir, username, "AppData", "Roaming", "Microsoft", "Windows", "Recent", "AutomaticDestinations")
		w.collectJumpListsFromDirectory(ctx, automaticDir, outDir, "automatic", username, manifest, constraints)

		// Collect custom jump lists
		customDir := filepath.Join(usersDir, username, "AppData", "Roaming", "Microsoft", "Windows", "Recent", "CustomDestinations")
		w.collectJumpListsFromDirectory(ctx, customDir, outDir, "custom", username, manifest, constraints)
	}

	return nil
}

// collectJumpListsFromDirectory collects jump list files from a specific directory.
func (w *WinJumpLists) collectJumpListsFromDirectory(ctx context.Context, sourceDir, outDir, fileType, username string, manifest *JumpListManifest, constraints *winutil.SizeConstraints) {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		// Don't treat as error if directory doesn't exist (user may not have jump lists)
		if !os.IsNotExist(err) {
			manifest.AddError(fmt.Sprintf("%s_%s", username, fileType), fmt.Sprintf("Failed to read directory: %v", err))
		}
		return
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		
		// Only collect jump list files based on extension
		if !w.isJumpListFile(filename, fileType) {
			continue
		}

		manifest.IncrementTotalFiles()

		srcPath := filepath.Join(sourceDir, filename)
		
		// Create destination filename with user prefix to avoid collisions
		destFilename := fmt.Sprintf("%s_%s_%s", username, fileType, filename)
		destPath := filepath.Join(outDir, destFilename)

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

		// Generate description based on file type
		note := w.generateFileNote(filename, fileType)

		// Add to manifest
		relPath := destFilename
		manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), fileType, username, note)
	}
}

// shouldSkipUser determines if a user directory should be skipped.
func (w *WinJumpLists) shouldSkipUser(username string) bool {
	skipUsers := []string{
		"All Users",
		"Default",
		"Default User", 
		"Public",
		"desktop.ini",
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

// isJumpListFile determines if a file is a jump list based on its name and type.
func (w *WinJumpLists) isJumpListFile(filename, fileType string) bool {
	lowerFilename := strings.ToLower(filename)
	
	switch fileType {
	case "automatic":
		// Automatic jump lists have .automaticDestinations-ms extension
		return strings.HasSuffix(lowerFilename, ".automaticdestinations-ms")
	case "custom":
		// Custom jump lists have .customDestinations-ms extension
		return strings.HasSuffix(lowerFilename, ".customdestinations-ms")
	default:
		return false
	}
}

// generateFileNote creates a descriptive note for jump list files.
func (w *WinJumpLists) generateFileNote(filename, fileType string) string {
	switch fileType {
	case "automatic":
		return fmt.Sprintf("Automatic jump list file (%s)", filename)
	case "custom":
		return fmt.Sprintf("Custom jump list file (%s)", filename)
	default:
		return fmt.Sprintf("Jump list file (%s)", filename)
	}
}