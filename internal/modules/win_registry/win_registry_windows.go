//go:build windows

package win_registry

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinRegistry represents the Windows registry hive collection module.
type WinRegistry struct{}

// NewWinRegistry creates a new Windows registry collection module.
func NewWinRegistry() *WinRegistry {
	return &WinRegistry{}
}

// Name returns the module's identifier.
func (w *WinRegistry) Name() string {
	return "windows/registry"
}

// Collect copies Windows registry hives and creates a manifest.
func (w *WinRegistry) Collect(ctx context.Context, outDir string) error {
	// Create the windows/registry subdirectory
	registryDir := filepath.Join(outDir, "windows", "registry")
	if err := winutil.EnsureDir(registryDir); err != nil {
		return fmt.Errorf("failed to create registry directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Try to enable backup/restore privileges
	backupPriv, restorePriv := false, false
	if err := winutil.EnableBackupRestorePrivileges(); err == nil {
		backupPriv, restorePriv = winutil.CheckPrivileges()
	}

	// Create manifest
	manifest := NewRegistryManifest(hostname, backupPriv, restorePriv)

	// Initialize size constraints
	constraints := winutil.NewSizeConstraints()

	// Collect system hives
	systemHives := GetSystemHives()
	for _, hive := range systemHives {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err := w.collectHive(ctx, hive, registryDir, manifest, constraints); err != nil {
			manifest.AddError(hive.Name, err.Error())
		}
	}

	// Collect user hives
	if err := w.collectUserHives(ctx, registryDir, manifest, constraints); err != nil {
		// Log error but continue - user hive collection failure shouldn't fail the whole module
		manifest.AddError("user_hives", err.Error())
	}

	// Write manifest
	manifestPath := filepath.Join(registryDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	// Return error if no hives were collected
	if len(manifest.Items) == 0 {
		return fmt.Errorf("no registry hives were successfully collected")
	}

	return nil
}

// collectHive attempts to collect a single registry hive using multiple methods.
func (w *WinRegistry) collectHive(ctx context.Context, hive RegistryHive, outDir string, manifest *RegistryManifest, constraints *winutil.SizeConstraints) error {
	destPath := filepath.Join(outDir, hive.Name+".hiv")

	// Method 1: Try direct file copy with backup semantics
	if err := w.copyHiveFile(hive.FilePath, destPath, hive.Note, manifest, constraints); err == nil {
		return nil
	}

	// Method 2: Try reg.exe export (fallback for system hives only)
	if !hive.IsUserHive && hive.RegKey != "" {
		if err := w.exportHiveWithReg(ctx, hive.RegKey, destPath, hive.Note, manifest, constraints); err == nil {
			return nil
		}
	}

	return fmt.Errorf("failed to collect hive %s using all methods", hive.Name)
}

// copyHiveFile attempts direct file copy of a registry hive.
func (w *WinRegistry) copyHiveFile(srcPath, destPath, note string, manifest *RegistryManifest, constraints *winutil.SizeConstraints) error {
	// Check if source file exists
	stat, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("source hive file not accessible: %w", err)
	}

	// Check size constraints
	if !constraints.CanCollectFile(stat.Size()) {
		return fmt.Errorf("hive file too large (%d bytes) or would exceed total limit", stat.Size())
	}

	// Use Windows-specific file copy with generous sharing
	size, sha256Hex, err := winutil.CopyFile(srcPath, destPath)
	if err != nil {
		return fmt.Errorf("failed to copy hive file: %w", err)
	}

	// Update constraints and manifest
	constraints.AddFileSize(size)
	relPath, _ := filepath.Rel(filepath.Dir(destPath), destPath)
	manifest.AddItem(relPath, size, sha256Hex, false, note, "copy")

	return nil
}

// exportHiveWithReg uses reg.exe to export a registry hive.
func (w *WinRegistry) exportHiveWithReg(ctx context.Context, regKey, destPath, note string, manifest *RegistryManifest, constraints *winutil.SizeConstraints) error {
	// Export using reg.exe
	if err := winutil.ExportRegistryHive(ctx, regKey, destPath); err != nil {
		return fmt.Errorf("reg export failed: %w", err)
	}

	// Get file info and compute hash
	stat, err := os.Stat(destPath)
	if err != nil {
		return fmt.Errorf("failed to stat exported hive: %w", err)
	}

	// Check if the exported file fits within constraints
	if !constraints.CanCollectFile(stat.Size()) {
		os.Remove(destPath) // Clean up
		return fmt.Errorf("exported hive too large (%d bytes)", stat.Size())
	}

	// Compute SHA-256 (read the file we just created)
	size, sha256Hex, truncated, err := winutil.FullCopy(destPath, destPath+".tmp")
	if err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}
	
	// Replace original with temp file that has computed hash
	os.Remove(destPath)
	os.Rename(destPath+".tmp", destPath)

	// Update constraints and manifest
	constraints.AddFileSize(size)
	relPath, _ := filepath.Rel(filepath.Dir(destPath), destPath)
	manifest.AddItem(relPath, size, sha256Hex, truncated, note, "reg_export")

	return nil
}

// collectUserHives enumerates users and collects their registry hives.
func (w *WinRegistry) collectUserHives(ctx context.Context, outDir string, manifest *RegistryManifest, constraints *winutil.SizeConstraints) error {
	usersDir := "C:\\Users"
	
	// Read users directory
	entries, err := os.ReadDir(usersDir)
	if err != nil {
		return fmt.Errorf("failed to read Users directory: %w", err)
	}

	userCount := 0
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
		
		// Skip system/service accounts
		if w.shouldSkipUser(username) {
			continue
		}

		userPath := filepath.Join(usersDir, username)
		userHives := GetUserHives(userPath, username)

		// Try to collect user hives (don't fail if some users can't be accessed)
		for _, hive := range userHives {
			if err := w.collectHive(ctx, hive, outDir, manifest, constraints); err != nil {
				manifest.AddError(fmt.Sprintf("user:%s:%s", username, hive.Name), err.Error())
			}
		}
		
		userCount++
	}

	if userCount == 0 {
		return fmt.Errorf("no user profiles found")
	}

	return nil
}

// shouldSkipUser determines if a user profile should be skipped.
func (w *WinRegistry) shouldSkipUser(username string) bool {
	skipList := []string{
		"All Users", "Default", "Default User", "Public",
		"WDAGUtilityAccount", "defaultuser0", "defaultuser100000",
	}

	username = strings.ToLower(username)
	for _, skip := range skipList {
		if username == strings.ToLower(skip) {
			return true
		}
	}

	// Skip usernames that look like service accounts
	if strings.HasPrefix(username, "nt ") || 
	   strings.HasPrefix(username, "iis_") ||
	   strings.HasPrefix(username, "iwam_") ||
	   strings.HasSuffix(username, "$") {
		return true
	}

	return false
}