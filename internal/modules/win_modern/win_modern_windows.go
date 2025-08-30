//go:build windows

package win_modern

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinModern represents the Windows modern artifacts collection module.
type WinModern struct{}

// NewWinModern creates a new Windows modern artifacts collection module.
func NewWinModern() *WinModern {
	return &WinModern{}
}

// Name returns the module's identifier.
func (w *WinModern) Name() string {
	return "windows/modern"
}

// Collect gathers Windows modern and cloud artifacts including OneDrive, Store apps, Cortana, Timeline, and Clipboard.
func (w *WinModern) Collect(ctx context.Context, outDir string) error {
	// Create the windows/modern subdirectory
	modernDir := filepath.Join(outDir, "windows", "modern")
	if err := winutil.EnsureDir(modernDir); err != nil {
		return fmt.Errorf("failed to create modern directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewModernManifest(hostname)
	constraints := winutil.NewSizeConstraints()

	// Collect per-user modern artifacts
	if err := w.collectPerUserModernArtifacts(ctx, modernDir, manifest, constraints); err != nil {
		manifest.AddError("per_user_modern", fmt.Sprintf("Failed to collect per-user modern artifacts: %v", err))
	}

	// Collect Windows Store apps information
	if err := w.collectStoreAppsInfo(ctx, modernDir, manifest); err != nil {
		manifest.AddError("store_apps", fmt.Sprintf("Failed to collect Store apps info: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(modernDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectPerUserModernArtifacts collects modern artifacts for each user profile.
func (w *WinModern) collectPerUserModernArtifacts(ctx context.Context, outDir string, manifest *ModernManifest, constraints *winutil.SizeConstraints) error {
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

		// Collect OneDrive artifacts
		w.collectOneDriveArtifacts(ctx, userProfileDir, userOutDir, manifest, constraints, username)

		// Collect Cortana artifacts
		w.collectCortanaArtifacts(ctx, userProfileDir, userOutDir, manifest, constraints, username)

		// Collect Timeline artifacts (Windows 10+)
		w.collectTimelineArtifacts(ctx, userProfileDir, userOutDir, manifest, constraints, username)

		// Collect Clipboard history (Windows 10 1809+)
		w.collectClipboardHistory(ctx, userProfileDir, userOutDir, manifest, constraints, username)
	}

	return nil
}

// collectOneDriveArtifacts collects OneDrive sync logs and metadata.
func (w *WinModern) collectOneDriveArtifacts(ctx context.Context, userProfileDir, userOutDir string, manifest *ModernManifest, constraints *winutil.SizeConstraints, username string) {
	// OneDrive logs are typically in AppData\Local\Microsoft\OneDrive\logs
	oneDriveLogDir := filepath.Join(userProfileDir, "AppData", "Local", "Microsoft", "OneDrive", "logs")
	
	if entries, err := os.ReadDir(oneDriveLogDir); err == nil {
		oneDriveOutDir := filepath.Join(userOutDir, "onedrive")
		if err := winutil.EnsureDir(oneDriveOutDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}

				filename := entry.Name()
				if strings.HasSuffix(strings.ToLower(filename), ".log") ||
				   strings.HasSuffix(strings.ToLower(filename), ".txt") {
					
					manifest.IncrementTotalFiles()
					srcPath := filepath.Join(oneDriveLogDir, filename)
					destPath := filepath.Join(oneDriveOutDir, filename)

					if stat, err := os.Stat(srcPath); err == nil {
						if size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints); err == nil {
							relPath := filepath.Join("users", username, "onedrive", filename)
							note := fmt.Sprintf("OneDrive log file for user %s (%s)", username, filename)
							manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "onedrive", note)
						}
					}
				}
			}
		}
	}

	// Also collect OneDrive settings
	oneDriveSettingsPath := filepath.Join(userProfileDir, "AppData", "Local", "Microsoft", "OneDrive", "settings")
	if entries, err := os.ReadDir(oneDriveSettingsPath); err == nil {
		oneDriveOutDir := filepath.Join(userOutDir, "onedrive")
		winutil.EnsureDir(oneDriveOutDir)
		
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			filename := entry.Name()
			if strings.HasSuffix(strings.ToLower(filename), ".dat") ||
			   strings.HasSuffix(strings.ToLower(filename), ".ini") {
				
				manifest.IncrementTotalFiles()
				srcPath := filepath.Join(oneDriveSettingsPath, filename)
				destPath := filepath.Join(oneDriveOutDir, "settings_"+filename)

				if stat, err := os.Stat(srcPath); err == nil {
					if size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints); err == nil {
						relPath := filepath.Join("users", username, "onedrive", "settings_"+filename)
						note := fmt.Sprintf("OneDrive settings file for user %s (%s)", username, filename)
						manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "onedrive", note)
					}
				}
			}
		}
	}
}

// collectCortanaArtifacts collects Cortana search index and voice data.
func (w *WinModern) collectCortanaArtifacts(ctx context.Context, userProfileDir, userOutDir string, manifest *ModernManifest, constraints *winutil.SizeConstraints, username string) {
	// Cortana data is typically in AppData\Local\Packages\Microsoft.Windows.Cortana_*
	packagesDir := filepath.Join(userProfileDir, "AppData", "Local", "Packages")
	
	if entries, err := os.ReadDir(packagesDir); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}

			packageName := entry.Name()
			if strings.Contains(strings.ToLower(packageName), "cortana") {
				cortanaDir := filepath.Join(packagesDir, packageName)
				cortanaOutDir := filepath.Join(userOutDir, "cortana")
				
				if err := winutil.EnsureDir(cortanaOutDir); err == nil {
					// Look for interesting Cortana files
					w.walkAndCollectFiles(ctx, cortanaDir, cortanaOutDir, manifest, constraints, username, "cortana", "Cortana")
				}
				break
			}
		}
	}
}

// collectTimelineArtifacts collects Windows Timeline activities database.
func (w *WinModern) collectTimelineArtifacts(ctx context.Context, userProfileDir, userOutDir string, manifest *ModernManifest, constraints *winutil.SizeConstraints, username string) {
	// Timeline database is in AppData\Local\ConnectedDevicesPlatform
	timelineDir := filepath.Join(userProfileDir, "AppData", "Local", "ConnectedDevicesPlatform")
	
	if entries, err := os.ReadDir(timelineDir); err == nil {
		timelineOutDir := filepath.Join(userOutDir, "timeline")
		if err := winutil.EnsureDir(timelineOutDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					// Look in subdirectories for ActivitiesCache.db
					subDir := filepath.Join(timelineDir, entry.Name())
					if subEntries, err := os.ReadDir(subDir); err == nil {
						for _, subEntry := range subEntries {
							filename := subEntry.Name()
							if strings.Contains(strings.ToLower(filename), "activitiescache") &&
							   strings.HasSuffix(strings.ToLower(filename), ".db") {
								
								manifest.IncrementTotalFiles()
								srcPath := filepath.Join(subDir, filename)
								destPath := filepath.Join(timelineOutDir, filename)

								if stat, err := os.Stat(srcPath); err == nil {
									if size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints); err == nil {
										relPath := filepath.Join("users", username, "timeline", filename)
										note := fmt.Sprintf("Windows Timeline activities database for user %s", username)
										manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "timeline", note)
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

// collectClipboardHistory collects Windows 10+ clipboard history.
func (w *WinModern) collectClipboardHistory(ctx context.Context, userProfileDir, userOutDir string, manifest *ModernManifest, constraints *winutil.SizeConstraints, username string) {
	// Clipboard history is in AppData\Local\Microsoft\Windows\Clipboard
	clipboardDir := filepath.Join(userProfileDir, "AppData", "Local", "Microsoft", "Windows", "Clipboard")
	
	if entries, err := os.ReadDir(clipboardDir); err == nil {
		clipboardOutDir := filepath.Join(userOutDir, "clipboard")
		if err := winutil.EnsureDir(clipboardOutDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}

				filename := entry.Name()
				manifest.IncrementTotalFiles()
				srcPath := filepath.Join(clipboardDir, filename)
				destPath := filepath.Join(clipboardOutDir, filename)

				if stat, err := os.Stat(srcPath); err == nil {
					if size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints); err == nil {
						relPath := filepath.Join("users", username, "clipboard", filename)
						note := fmt.Sprintf("Windows clipboard history file for user %s (%s)", username, filename)
						manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "clipboard", note)
					}
				}
			}
		}
	}
}

// collectStoreAppsInfo collects Windows Store apps information.
func (w *WinModern) collectStoreAppsInfo(ctx context.Context, outDir string, manifest *ModernManifest) error {
	outputPath := filepath.Join(outDir, "store_apps_info.txt")

	// Use PowerShell to get installed Store apps
	psScript := `Get-AppxPackage | Select-Object Name, Version, InstallLocation, PackageFullName | Format-Table -AutoSize`
	args := []string{"-Command", psScript}
	output, err := winutil.RunCommandWithOutput(ctx, "powershell", args)
	if err != nil {
		return fmt.Errorf("failed to run PowerShell Store apps command: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write Store apps info: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("store_apps_info.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "store_apps", "Windows Store apps information from PowerShell Get-AppxPackage")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// walkAndCollectFiles recursively walks a directory and collects interesting files.
func (w *WinModern) walkAndCollectFiles(ctx context.Context, sourceDir, outDir string, manifest *ModernManifest, constraints *winutil.SizeConstraints, username, fileType, description string) {
	filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}

		filename := d.Name()
		if strings.HasSuffix(strings.ToLower(filename), ".db") ||
		   strings.HasSuffix(strings.ToLower(filename), ".log") ||
		   strings.HasSuffix(strings.ToLower(filename), ".txt") {
			
			manifest.IncrementTotalFiles()
			
			// Get relative path from source
			relFromSource, _ := filepath.Rel(sourceDir, path)
			destPath := filepath.Join(outDir, relFromSource)
			
			// Ensure destination directory exists
			destDir := filepath.Dir(destPath)
			winutil.EnsureDir(destDir)

			if stat, err := os.Stat(path); err == nil {
				if size, sha256Hex, truncated, err := winutil.SmartCopy(path, destPath, constraints); err == nil {
					relPath := filepath.Join("users", username, fileType, relFromSource)
					note := fmt.Sprintf("%s file for user %s (%s)", description, username, filename)
					manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), fileType, note)
				}
			}
		}
		
		return nil
	})
}

// isSystemProfile checks if a username represents a system profile that should be skipped.
func (w *WinModern) isSystemProfile(username string) bool {
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