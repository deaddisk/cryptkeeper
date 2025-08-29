//go:build windows

package win_browser

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

type WinBrowser struct{}

func NewWinBrowser() *WinBrowser {
	return &WinBrowser{}
}

func (w *WinBrowser) Name() string {
	return "windows/browser"
}

func (w *WinBrowser) Collect(ctx context.Context, outDir string) error {
	browserDir := filepath.Join(outDir, "windows", "browser")
	if err := winutil.EnsureDir(browserDir); err != nil {
		return fmt.Errorf("failed to create browser directory: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	manifest := NewBrowserManifest(hostname)
	constraints := winutil.NewSizeConstraints()

	// Enumerate user profiles for browser artifacts
	if err := w.collectPerUserBrowserArtifacts(ctx, browserDir, manifest, constraints); err != nil {
		manifest.AddError("browser_artifacts", fmt.Sprintf("Failed to collect browser artifacts: %v", err))
	}

	manifestPath := filepath.Join(browserDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

func (w *WinBrowser) collectPerUserBrowserArtifacts(ctx context.Context, outDir string, manifest *BrowserManifest, constraints *winutil.SizeConstraints) error {
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

		// Collect Chromium-based browsers
		w.collectChromiumArtifacts(ctx, userProfileDir, userOutDir, manifest, constraints, username, "Chrome", "Google\\Chrome\\User Data")
		w.collectChromiumArtifacts(ctx, userProfileDir, userOutDir, manifest, constraints, username, "Edge", "Microsoft\\Edge\\User Data")

		// Collect Firefox artifacts
		w.collectFirefoxArtifacts(ctx, userProfileDir, userOutDir, manifest, constraints, username)
	}

	return nil
}

func (w *WinBrowser) collectChromiumArtifacts(ctx context.Context, userProfileDir, userOutDir string, manifest *BrowserManifest, constraints *winutil.SizeConstraints, username, browserName, relativePath string) {
	browserDataDir := filepath.Join(userProfileDir, "AppData", "Local", relativePath)
	
	// Look for user profiles (Default, Profile 1, etc.)
	profiles, err := os.ReadDir(browserDataDir)
	if err != nil {
		return
	}

	for _, profile := range profiles {
		if !profile.IsDir() {
			continue
		}

		profileName := profile.Name()
		if !strings.HasPrefix(profileName, "Default") && !strings.HasPrefix(profileName, "Profile") {
			continue
		}

		profileDir := filepath.Join(browserDataDir, profileName)
		outputProfileDir := filepath.Join(userOutDir, strings.ToLower(browserName), profileName)

		if err := winutil.EnsureDir(outputProfileDir); err != nil {
			continue
		}

		// Collect key database files
		dbFiles := []string{"History", "Cookies", "Login Data"}
		for _, dbFile := range dbFiles {
			srcPath := filepath.Join(profileDir, dbFile)
			if stat, err := os.Stat(srcPath); err == nil {
				manifest.IncrementTotalFiles()
				destPath := filepath.Join(outputProfileDir, dbFile)
				
				size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints)
				if err != nil {
					manifest.AddError(srcPath, fmt.Sprintf("Failed to copy %s: %v", dbFile, err))
					continue
				}

				relPath := filepath.Join("users", username, strings.ToLower(browserName), profileName, dbFile)
				fileType := strings.ToLower(strings.Replace(dbFile, " ", "_", -1))
				note := fmt.Sprintf("%s %s database for user %s profile %s", browserName, dbFile, username, profileName)

				manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), fileType, note)
			}
		}
	}
}

func (w *WinBrowser) collectFirefoxArtifacts(ctx context.Context, userProfileDir, userOutDir string, manifest *BrowserManifest, constraints *winutil.SizeConstraints, username string) {
	firefoxDir := filepath.Join(userProfileDir, "AppData", "Roaming", "Mozilla", "Firefox", "Profiles")
	
	profiles, err := os.ReadDir(firefoxDir)
	if err != nil {
		return
	}

	for _, profile := range profiles {
		if !profile.IsDir() {
			continue
		}

		profileName := profile.Name()
		profileDir := filepath.Join(firefoxDir, profileName)
		outputProfileDir := filepath.Join(userOutDir, "firefox", profileName)

		if err := winutil.EnsureDir(outputProfileDir); err != nil {
			continue
		}

		// Collect key SQLite databases
		dbFiles := []string{"places.sqlite", "cookies.sqlite"}
		for _, dbFile := range dbFiles {
			srcPath := filepath.Join(profileDir, dbFile)
			if stat, err := os.Stat(srcPath); err == nil {
				manifest.IncrementTotalFiles()
				destPath := filepath.Join(outputProfileDir, dbFile)
				
				size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints)
				if err != nil {
					manifest.AddError(srcPath, fmt.Sprintf("Failed to copy %s: %v", dbFile, err))
					continue
				}

				relPath := filepath.Join("users", username, "firefox", profileName, dbFile)
				fileType := strings.ToLower(strings.Replace(dbFile, ".sqlite", "", -1))
				note := fmt.Sprintf("Firefox %s database for user %s profile %s", dbFile, username, profileName)

				manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), fileType, note)
			}
		}
	}
}

func (w *WinBrowser) isSystemProfile(username string) bool {
	systemProfiles := []string{"All Users", "Default", "Default User", "Public", "WDAGUtilityAccount"}
	lowerUsername := strings.ToLower(username)
	for _, profile := range systemProfiles {
		if lowerUsername == strings.ToLower(profile) {
			return true
		}
	}
	return false
}