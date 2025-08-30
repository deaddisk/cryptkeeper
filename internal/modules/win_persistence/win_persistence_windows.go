//go:build windows

package win_persistence

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinPersistence represents the Windows persistence artifacts collection module.
type WinPersistence struct{}

// NewWinPersistence creates a new Windows persistence artifacts collection module.
func NewWinPersistence() *WinPersistence {
	return &WinPersistence{}
}

// Name returns the module's identifier.
func (w *WinPersistence) Name() string {
	return "windows/persistence"
}

// Collect gathers Windows persistence and malware hunting artifacts.
func (w *WinPersistence) Collect(ctx context.Context, outDir string) error {
	// Create the windows/persistence subdirectory
	persistenceDir := filepath.Join(outDir, "windows", "persistence")
	if err := winutil.EnsureDir(persistenceDir); err != nil {
		return fmt.Errorf("failed to create persistence directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewPersistenceManifest(hostname)
	constraints := winutil.NewSizeConstraints()

	// Collect autorun locations
	if err := w.collectAutoRunLocations(ctx, persistenceDir, manifest); err != nil {
		manifest.AddError("autorun_locations", fmt.Sprintf("Failed to collect autorun locations: %v", err))
	}

	// Collect per-user persistence artifacts
	if err := w.collectPerUserPersistence(ctx, persistenceDir, manifest, constraints); err != nil {
		manifest.AddError("per_user_persistence", fmt.Sprintf("Failed to collect per-user persistence: %v", err))
	}

	// Collect COM objects information
	if err := w.collectCOMObjects(ctx, persistenceDir, manifest); err != nil {
		manifest.AddError("com_objects", fmt.Sprintf("Failed to collect COM objects: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(persistenceDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectAutoRunLocations collects comprehensive autorun locations using registry queries.
func (w *WinPersistence) collectAutoRunLocations(ctx context.Context, outDir string, manifest *PersistenceManifest) error {
	outputPath := filepath.Join(outDir, "autorun_locations.txt")

	// Common autorun registry locations
	autorunKeys := []string{
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
		"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
		"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run",
		"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon",
		"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options",
	}

	output := "Windows Autorun Locations Analysis:\n\n"

	for _, key := range autorunKeys {
		args := []string{"query", key, "/s"}
		if result, err := winutil.RunCommandWithOutput(ctx, "reg", args); err == nil {
			output += fmt.Sprintf("=== %s ===\n", key)
			output += string(result)
			output += "\n\n"
		} else {
			output += fmt.Sprintf("=== %s ===\n", key)
			output += fmt.Sprintf("Error querying key: %v\n\n", err)
		}
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write autorun locations: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("autorun_locations.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "autoruns", "Comprehensive autorun registry locations analysis")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectPerUserPersistence collects per-user persistence artifacts including ShellBags and cache files.
func (w *WinPersistence) collectPerUserPersistence(ctx context.Context, outDir string, manifest *PersistenceManifest, constraints *winutil.SizeConstraints) error {
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
		if !userEntry.IsDir() || w.isSystemProfile(userEntry.Name()) {
			continue
		}

		username := userEntry.Name()
		userProfileDir := filepath.Join(usersDir, username)
		userOutDir := filepath.Join(outDir, "users", username)

		if err := winutil.EnsureDir(userOutDir); err != nil {
			continue
		}

		// Collect thumbnail cache
		w.collectThumbnailCache(ctx, userProfileDir, userOutDir, manifest, constraints, username)

		// Collect icon cache
		w.collectIconCache(ctx, userProfileDir, userOutDir, manifest, constraints, username)

		// Note: ShellBags are in the registry (NTUSER.DAT) which is already collected by win_registry
		w.createShellBagsNote(userOutDir, manifest, username)
	}

	return nil
}

// collectThumbnailCache collects Windows thumbnail cache files.
func (w *WinPersistence) collectThumbnailCache(ctx context.Context, userProfileDir, userOutDir string, manifest *PersistenceManifest, constraints *winutil.SizeConstraints, username string) {
	// Thumbnail cache locations vary by Windows version
	thumbnailPaths := []string{
		filepath.Join(userProfileDir, "AppData", "Local", "Microsoft", "Windows", "Explorer"), // Windows 8+
		filepath.Join(userProfileDir, "AppData", "Local", "Thumbnails"), // Windows 7
	}

	for _, thumbnailPath := range thumbnailPaths {
		if entries, err := os.ReadDir(thumbnailPath); err == nil {
			thumbOutDir := filepath.Join(userOutDir, "thumbnails")
			if err := winutil.EnsureDir(thumbOutDir); err == nil {
				for _, entry := range entries {
					if entry.IsDir() {
						continue
					}

					filename := entry.Name()
					if strings.Contains(strings.ToLower(filename), "thumb") ||
					   strings.HasSuffix(strings.ToLower(filename), ".db") {
						
						manifest.IncrementTotalFiles()
						srcPath := filepath.Join(thumbnailPath, filename)
						destPath := filepath.Join(thumbOutDir, filename)

						if stat, err := os.Stat(srcPath); err == nil {
							if size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints); err == nil {
								relPath := filepath.Join("users", username, "thumbnails", filename)
								note := fmt.Sprintf("Windows thumbnail cache file for user %s", username)
								manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "thumbnails", note)
							}
						}
					}
				}
			}
			break // Only process the first valid path found
		}
	}
}

// collectIconCache collects Windows icon cache files.
func (w *WinPersistence) collectIconCache(ctx context.Context, userProfileDir, userOutDir string, manifest *PersistenceManifest, constraints *winutil.SizeConstraints, username string) {
	// Icon cache is typically in AppData\Local\IconCache.db (Windows 7) or AppData\Local\Microsoft\Windows\Explorer (Windows 8+)
	iconCachePaths := []string{
		filepath.Join(userProfileDir, "AppData", "Local", "IconCache.db"),
		filepath.Join(userProfileDir, "AppData", "Local", "Microsoft", "Windows", "Explorer", "iconcache_*.db"),
	}

	iconOutDir := filepath.Join(userOutDir, "iconcache")
	if err := winutil.EnsureDir(iconOutDir); err != nil {
		return
	}

	for _, iconPath := range iconCachePaths {
		if strings.Contains(iconPath, "*") {
			// Handle wildcard path
			dir := filepath.Dir(iconPath)
			pattern := filepath.Base(iconPath)
			
			if entries, err := os.ReadDir(dir); err == nil {
				for _, entry := range entries {
					filename := entry.Name()
					if matched, _ := filepath.Match(pattern, filename); matched {
						manifest.IncrementTotalFiles()
						srcPath := filepath.Join(dir, filename)
						destPath := filepath.Join(iconOutDir, filename)

						if stat, err := os.Stat(srcPath); err == nil {
							if size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints); err == nil {
								relPath := filepath.Join("users", username, "iconcache", filename)
								note := fmt.Sprintf("Windows icon cache file for user %s", username)
								manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "iconcache", note)
							}
						}
					}
				}
			}
		} else {
			// Handle direct path
			if stat, err := os.Stat(iconPath); err == nil {
				manifest.IncrementTotalFiles()
				filename := filepath.Base(iconPath)
				destPath := filepath.Join(iconOutDir, filename)

				if size, sha256Hex, truncated, err := winutil.SmartCopy(iconPath, destPath, constraints); err == nil {
					relPath := filepath.Join("users", username, "iconcache", filename)
					note := fmt.Sprintf("Windows icon cache file for user %s", username)
					manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "iconcache", note)
				}
			}
		}
	}
}

// createShellBagsNote creates a note about ShellBags being in the registry.
func (w *WinPersistence) createShellBagsNote(userOutDir string, manifest *PersistenceManifest, username string) {
	noteContent := fmt.Sprintf("ShellBags Information for user %s:\n\n", username)
	noteContent += "ShellBags data is stored in the Windows Registry and is captured by the win_registry module.\n"
	noteContent += "ShellBags contain information about folder access history and window positions.\n\n"
	noteContent += "Registry locations:\n"
	noteContent += "- NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\Bags\n"
	noteContent += "- NTUSER.DAT\\Software\\Microsoft\\Windows\\Shell\\BagMRU\n"
	noteContent += "- NTUSER.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\Bags\n"
	noteContent += "- NTUSER.DAT\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU\n"

	notePath := filepath.Join(userOutDir, "shellbags_info.txt")
	if err := os.WriteFile(notePath, []byte(noteContent), 0644); err == nil {
		if stat, err := os.Stat(notePath); err == nil {
			if sha256Hex, err := winutil.HashFile(notePath); err == nil {
				relPath := filepath.Join("users", username, "shellbags_info.txt")
				note := fmt.Sprintf("ShellBags registry information for user %s", username)
				manifest.AddItem(relPath, stat.Size(), sha256Hex, false, stat.ModTime(), "shellbags", note)
			}
		}
	}
}

// collectCOMObjects collects COM objects registration information.
func (w *WinPersistence) collectCOMObjects(ctx context.Context, outDir string, manifest *PersistenceManifest) error {
	outputPath := filepath.Join(outDir, "com_objects.txt")

	// Query COM objects from registry
	comKeys := []string{
		"HKLM\\SOFTWARE\\Classes\\CLSID",
		"HKCU\\SOFTWARE\\Classes\\CLSID",
	}

	output := "COM Objects Registration Information:\n\n"

	for _, key := range comKeys {
		args := []string{"query", key, "/f", "InprocServer32", "/s", "/k"}
		if result, err := winutil.RunCommandWithOutput(ctx, "reg", args); err == nil {
			output += fmt.Sprintf("=== %s (InprocServer32) ===\n", key)
			output += string(result)
			output += "\n\n"
		}
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write COM objects: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("com_objects.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "com_objects", "COM objects registration information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// isSystemProfile checks if a username represents a system profile that should be skipped.
func (w *WinPersistence) isSystemProfile(username string) bool {
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