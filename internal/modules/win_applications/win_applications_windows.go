//go:build windows

package win_applications

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinApplications represents the Windows application artifacts collection module.
type WinApplications struct{}

// NewWinApplications creates a new Windows application artifacts collection module.
func NewWinApplications() *WinApplications {
	return &WinApplications{}
}

// Name returns the module's identifier.
func (w *WinApplications) Name() string {
	return "windows/applications"
}

// Collect gathers Windows application-specific artifacts including Office, Skype, Teams, Outlook, and Antivirus.
func (w *WinApplications) Collect(ctx context.Context, outDir string) error {
	// Create the windows/applications subdirectory
	appsDir := filepath.Join(outDir, "windows", "applications")
	if err := winutil.EnsureDir(appsDir); err != nil {
		return fmt.Errorf("failed to create applications directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewApplicationManifest(hostname)
	constraints := winutil.NewSizeConstraints()

	// Collect per-user application artifacts
	if err := w.collectPerUserApplications(ctx, appsDir, manifest, constraints); err != nil {
		manifest.AddError("per_user_applications", fmt.Sprintf("Failed to collect per-user applications: %v", err))
	}

	// Collect Windows Defender logs
	if err := w.collectWindowsDefender(ctx, appsDir, manifest, constraints); err != nil {
		manifest.AddError("windows_defender", fmt.Sprintf("Failed to collect Windows Defender artifacts: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(appsDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectPerUserApplications collects application artifacts for each user profile.
func (w *WinApplications) collectPerUserApplications(ctx context.Context, outDir string, manifest *ApplicationManifest, constraints *winutil.SizeConstraints) error {
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

		// Collect Microsoft Office artifacts
		w.collectOfficeArtifacts(ctx, userProfileDir, userOutDir, manifest, constraints, username)

		// Collect Skype artifacts
		w.collectSkypeArtifacts(ctx, userProfileDir, userOutDir, manifest, constraints, username)

		// Collect Microsoft Teams artifacts
		w.collectTeamsArtifacts(ctx, userProfileDir, userOutDir, manifest, constraints, username)

		// Collect Outlook artifacts
		w.collectOutlookArtifacts(ctx, userProfileDir, userOutDir, manifest, constraints, username)
	}

	return nil
}

// collectOfficeArtifacts collects Microsoft Office recent files and trusted locations.
func (w *WinApplications) collectOfficeArtifacts(ctx context.Context, userProfileDir, userOutDir string, manifest *ApplicationManifest, constraints *winutil.SizeConstraints, username string) {
	// Office recent files are typically in AppData\Roaming\Microsoft\Office\Recent
	officeRecentDir := filepath.Join(userProfileDir, "AppData", "Roaming", "Microsoft", "Office", "Recent")
	if entries, err := os.ReadDir(officeRecentDir); err == nil {
		officeOutDir := filepath.Join(userOutDir, "office")
		if err := winutil.EnsureDir(officeOutDir); err == nil {
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}

				manifest.IncrementTotalFiles()
				srcPath := filepath.Join(officeRecentDir, entry.Name())
				destPath := filepath.Join(officeOutDir, entry.Name())

				if stat, err := os.Stat(srcPath); err == nil {
					if size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints); err == nil {
						relPath := filepath.Join("users", username, "office", entry.Name())
						note := fmt.Sprintf("Microsoft Office recent file for user %s", username)
						manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "office", note)
					}
				}
			}
		}
	}
}

// collectSkypeArtifacts collects Skype chat logs and call history.
func (w *WinApplications) collectSkypeArtifacts(ctx context.Context, userProfileDir, userOutDir string, manifest *ApplicationManifest, constraints *winutil.SizeConstraints, username string) {
	// Skype data is typically in AppData\Roaming\Skype
	skypeDir := filepath.Join(userProfileDir, "AppData", "Roaming", "Skype")
	if entries, err := os.ReadDir(skypeDir); err == nil {
		skypeOutDir := filepath.Join(userOutDir, "skype")
		if err := winutil.EnsureDir(skypeOutDir); err == nil {
			for _, entry := range entries {
				if !entry.IsDir() {
					continue
				}

				// Look for main.db files which contain Skype data
				userSkypeDir := filepath.Join(skypeDir, entry.Name())
				mainDbPath := filepath.Join(userSkypeDir, "main.db")
				
				if stat, err := os.Stat(mainDbPath); err == nil {
					manifest.IncrementTotalFiles()
					destPath := filepath.Join(skypeOutDir, fmt.Sprintf("%s_main.db", entry.Name()))
					
					if size, sha256Hex, truncated, err := winutil.SmartCopy(mainDbPath, destPath, constraints); err == nil {
						relPath := filepath.Join("users", username, "skype", fmt.Sprintf("%s_main.db", entry.Name()))
						note := fmt.Sprintf("Skype database for user %s account %s", username, entry.Name())
						manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "skype", note)
					}
				}
			}
		}
	}
}

// collectTeamsArtifacts collects Microsoft Teams artifacts.
func (w *WinApplications) collectTeamsArtifacts(ctx context.Context, userProfileDir, userOutDir string, manifest *ApplicationManifest, constraints *winutil.SizeConstraints, username string) {
	// Teams data is typically in AppData\Roaming\Microsoft\Teams
	teamsDir := filepath.Join(userProfileDir, "AppData", "Roaming", "Microsoft", "Teams")
	
	// Look for important Teams files
	teamsFiles := []struct {
		relativePath string
		description  string
	}{
		{"logs.txt", "Teams application logs"},
		{"desktop-config.json", "Teams desktop configuration"},
		{"storage.json", "Teams storage configuration"},
	}

	teamsOutDir := filepath.Join(userOutDir, "teams")
	if err := winutil.EnsureDir(teamsOutDir); err == nil {
		for _, file := range teamsFiles {
			srcPath := filepath.Join(teamsDir, file.relativePath)
			if stat, err := os.Stat(srcPath); err == nil {
				manifest.IncrementTotalFiles()
				destPath := filepath.Join(teamsOutDir, filepath.Base(file.relativePath))
				
				if size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints); err == nil {
					relPath := filepath.Join("users", username, "teams", filepath.Base(file.relativePath))
					note := fmt.Sprintf("%s for user %s", file.description, username)
					manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "teams", note)
				}
			}
		}
	}
}

// collectOutlookArtifacts collects Outlook PST/OST files (metadata only due to size).
func (w *WinApplications) collectOutlookArtifacts(ctx context.Context, userProfileDir, userOutDir string, manifest *ApplicationManifest, constraints *winutil.SizeConstraints, username string) {
	// Outlook data files are typically in AppData\Local\Microsoft\Outlook
	outlookDir := filepath.Join(userProfileDir, "AppData", "Local", "Microsoft", "Outlook")
	
	if entries, err := os.ReadDir(outlookDir); err == nil {
		outlookOutDir := filepath.Join(userOutDir, "outlook")
		if err := winutil.EnsureDir(outlookOutDir); err == nil {
			infoContent := fmt.Sprintf("Outlook Data Files for user %s:\n\n", username)
			
			for _, entry := range entries {
				if entry.IsDir() {
					continue
				}

				filename := entry.Name()
				if strings.HasSuffix(strings.ToLower(filename), ".pst") || 
				   strings.HasSuffix(strings.ToLower(filename), ".ost") {
					
					srcPath := filepath.Join(outlookDir, filename)
					if stat, err := os.Stat(srcPath); err == nil {
						manifest.IncrementTotalFiles()
						
						// Add file metadata to info file instead of copying large email files
						infoContent += fmt.Sprintf("File: %s\n", filename)
						infoContent += fmt.Sprintf("Size: %d bytes (%.2f MB)\n", stat.Size(), float64(stat.Size())/1024/1024)
						infoContent += fmt.Sprintf("Modified: %s\n", stat.ModTime().Format("2006-01-02 15:04:05"))
						infoContent += fmt.Sprintf("Note: Email data file not copied due to size and privacy constraints\n\n")
					}
				}
			}
			
			// Write info file
			if len(infoContent) > 50 { // Only if we found files
				infoPath := filepath.Join(outlookOutDir, "outlook_files_info.txt")
				if err := os.WriteFile(infoPath, []byte(infoContent), 0644); err == nil {
					if stat, err := os.Stat(infoPath); err == nil {
						if sha256Hex, err := winutil.HashFile(infoPath); err == nil {
							relPath := filepath.Join("users", username, "outlook", "outlook_files_info.txt")
							note := fmt.Sprintf("Outlook data files metadata for user %s", username)
							manifest.AddItem(relPath, stat.Size(), sha256Hex, false, stat.ModTime(), "outlook", note)
						}
					}
				}
			}
		}
	}
}

// collectWindowsDefender collects Windows Defender logs and quarantine information.
func (w *WinApplications) collectWindowsDefender(ctx context.Context, outDir string, manifest *ApplicationManifest, constraints *winutil.SizeConstraints) error {
	defenderOutDir := filepath.Join(outDir, "windows_defender")
	if err := winutil.EnsureDir(defenderOutDir); err != nil {
		return err
	}

	// Collect Windows Defender logs from ProgramData
	programData := os.Getenv("ProgramData")
	if programData == "" {
		systemDrive := os.Getenv("SystemDrive")
		if systemDrive == "" {
			systemDrive = "C:"
		}
		programData = filepath.Join(systemDrive, "ProgramData")
	}

	defenderLogDir := filepath.Join(programData, "Microsoft", "Windows Defender", "Support")
	if entries, err := os.ReadDir(defenderLogDir); err == nil {
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			filename := entry.Name()
			if strings.HasSuffix(strings.ToLower(filename), ".log") ||
			   strings.HasSuffix(strings.ToLower(filename), ".txt") {
				
				manifest.IncrementTotalFiles()
				srcPath := filepath.Join(defenderLogDir, filename)
				destPath := filepath.Join(defenderOutDir, filename)

				if stat, err := os.Stat(srcPath); err == nil {
					if size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints); err == nil {
						relPath := filepath.Join("windows_defender", filename)
						note := fmt.Sprintf("Windows Defender log file (%s)", filename)
						manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "antivirus", note)
					}
				}
			}
		}
	}

	return nil
}

// isSystemProfile checks if a username represents a system profile that should be skipped.
func (w *WinApplications) isSystemProfile(username string) bool {
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