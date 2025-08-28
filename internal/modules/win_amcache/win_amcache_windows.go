//go:build windows

package win_amcache

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"cryptkeeper/internal/winutil"
)

// WinAmcache represents the Windows Amcache collection module.
type WinAmcache struct{}

// NewWinAmcache creates a new Windows Amcache collection module.
func NewWinAmcache() *WinAmcache {
	return &WinAmcache{}
}

// Name returns the module's identifier.
func (w *WinAmcache) Name() string {
	return "windows/amcache"
}

// Collect copies Windows Amcache files and creates a manifest.
func (w *WinAmcache) Collect(ctx context.Context, outDir string) error {
	// Create the windows/amcache subdirectory
	amcacheDir := filepath.Join(outDir, "windows", "amcache")
	if err := winutil.EnsureDir(amcacheDir); err != nil {
		return fmt.Errorf("failed to create amcache directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Determine Amcache paths
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}

	amcachePath := filepath.Join(systemRoot, "AppCompat", "Programs", "Amcache.hve")
	legacyPath := filepath.Join(systemRoot, "AppCompat", "Programs", "RecentFileCache.bcf")

	// Create manifest
	manifest := NewAmcacheManifest(hostname, amcachePath, legacyPath)

	// Initialize size constraints
	constraints := winutil.NewSizeConstraints()

	// Try to collect primary Amcache.hve file
	if err := w.collectAmcacheFile(ctx, amcachePath, amcacheDir, "Amcache.hve", "amcache", "Primary Amcache registry hive", manifest, constraints); err != nil {
		manifest.AddError("Amcache.hve", err.Error())
	}

	// Try to collect legacy RecentFileCache.bcf (older Windows versions)
	if err := w.collectAmcacheFile(ctx, legacyPath, amcacheDir, "RecentFileCache.bcf", "recentfilecache", "Legacy RecentFileCache (pre-Windows 8)", manifest, constraints); err != nil {
		manifest.AddError("RecentFileCache.bcf", err.Error())
	}

	// Also collect any transaction log files associated with Amcache.hve
	w.collectAmcacheLogFiles(ctx, filepath.Dir(amcachePath), amcacheDir, manifest, constraints)

	// Write manifest
	manifestPath := filepath.Join(amcacheDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	// Return success even if no files collected - Amcache may not exist on some systems
	return nil
}

// collectAmcacheFile collects a single Amcache-related file.
func (w *WinAmcache) collectAmcacheFile(ctx context.Context, srcPath, outDir, destFilename, fileType, note string, manifest *AmcacheManifest, constraints *winutil.SizeConstraints) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	// Check if source file exists
	stat, err := os.Stat(srcPath)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file does not exist (expected on some systems)")
		}
		return fmt.Errorf("failed to stat file: %w", err)
	}

	destPath := filepath.Join(outDir, destFilename)

	// Use smart copy with size constraints
	size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints)
	if err != nil {
		return fmt.Errorf("failed to copy file: %w", err)
	}

	// Add to manifest
	relPath := filepath.Base(destPath)
	manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), fileType, note)

	return nil
}

// collectAmcacheLogFiles collects transaction log files (.LOG, .LOG1, .LOG2) associated with Amcache.hve.
func (w *WinAmcache) collectAmcacheLogFiles(ctx context.Context, amcacheBaseDir, outDir string, manifest *AmcacheManifest, constraints *winutil.SizeConstraints) {
	// Common log file extensions for registry hives
	logExtensions := []string{".LOG", ".LOG1", ".LOG2"}
	baseName := "Amcache.hve"

	for _, ext := range logExtensions {
		select {
		case <-ctx.Done():
			return
		default:
		}

		logPath := filepath.Join(amcacheBaseDir, baseName+ext)
		destFilename := baseName + ext

		// Try to collect log file (don't treat as error if missing)
		if err := w.collectAmcacheFile(ctx, logPath, outDir, destFilename, "amcache_log", 
			fmt.Sprintf("Amcache transaction log (%s)", ext), manifest, constraints); err != nil {
			// Only add as error if it's not a "file doesn't exist" error
			if !os.IsNotExist(err) {
				manifest.AddError(destFilename, err.Error())
			}
		}
	}
}