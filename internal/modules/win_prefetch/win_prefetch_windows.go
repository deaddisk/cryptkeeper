//go:build windows

package win_prefetch

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinPrefetch represents the Windows prefetch file collection module.
type WinPrefetch struct{}

// NewWinPrefetch creates a new Windows prefetch collection module.
func NewWinPrefetch() *WinPrefetch {
	return &WinPrefetch{}
}

// Name returns the module's identifier.
func (w *WinPrefetch) Name() string {
	return "windows/prefetch"
}

// Collect copies Windows prefetch files and creates a manifest.
func (w *WinPrefetch) Collect(ctx context.Context, outDir string) error {
	// Create the windows/prefetch subdirectory
	prefetchDir := filepath.Join(outDir, "windows", "prefetch")
	if err := winutil.EnsureDir(prefetchDir); err != nil {
		return fmt.Errorf("failed to create prefetch directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Determine prefetch path
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}
	prefetchPath := filepath.Join(systemRoot, "Prefetch")

	// Check if prefetch is enabled by checking if directory exists and has .pf files
	prefetchEnabled, totalFiles := w.checkPrefetchStatus(prefetchPath)

	// Create manifest
	manifest := NewPrefetchManifest(hostname, prefetchEnabled, prefetchPath)
	manifest.SetTotalFiles(totalFiles)

	// If prefetch is not enabled or no files found, still create manifest
	if !prefetchEnabled || totalFiles == 0 {
		manifest.AddError("prefetch_directory", "Prefetch is disabled or no .pf files found")
		
		// Write manifest and return success (this is expected on many systems)
		manifestPath := filepath.Join(prefetchDir, "manifest.json")
		if err := manifest.WriteManifest(manifestPath); err != nil {
			return fmt.Errorf("failed to write manifest: %w", err)
		}
		return nil
	}

	// Initialize size constraints
	constraints := winutil.NewSizeConstraints()

	// Collect all .pf files
	if err := w.collectPrefetchFiles(ctx, prefetchPath, prefetchDir, manifest, constraints); err != nil {
		return fmt.Errorf("failed to collect prefetch files: %w", err)
	}

	// Write manifest
	manifestPath := filepath.Join(prefetchDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// checkPrefetchStatus checks if prefetch is enabled and counts .pf files.
func (w *WinPrefetch) checkPrefetchStatus(prefetchPath string) (enabled bool, totalFiles int) {
	// Check if prefetch directory exists
	if _, err := os.Stat(prefetchPath); os.IsNotExist(err) {
		return false, 0
	}

	// Count .pf files
	entries, err := os.ReadDir(prefetchPath)
	if err != nil {
		return false, 0
	}

	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(strings.ToLower(entry.Name()), ".pf") {
			totalFiles++
		}
	}

	return totalFiles > 0, totalFiles
}

// collectPrefetchFiles collects all .pf files from the prefetch directory.
func (w *WinPrefetch) collectPrefetchFiles(ctx context.Context, prefetchPath, outDir string, manifest *PrefetchManifest, constraints *winutil.SizeConstraints) error {
	// Read prefetch directory
	entries, err := os.ReadDir(prefetchPath)
	if err != nil {
		return fmt.Errorf("failed to read prefetch directory: %w", err)
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip directories and non-.pf files
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".pf") {
			continue
		}

		srcPath := filepath.Join(prefetchPath, entry.Name())
		destPath := filepath.Join(outDir, entry.Name())

		// Collect the prefetch file
		if err := w.collectPrefetchFile(srcPath, destPath, manifest, constraints); err != nil {
			manifest.AddError(entry.Name(), err.Error())
			continue
		}
	}

	return nil
}

// collectPrefetchFile collects a single prefetch file.
func (w *WinPrefetch) collectPrefetchFile(srcPath, destPath string, manifest *PrefetchManifest, constraints *winutil.SizeConstraints) error {
	// Get file info
	stat, err := os.Stat(srcPath)
	if err != nil {
		return fmt.Errorf("failed to stat prefetch file: %w", err)
	}

	// Use smart copy with size constraints
	size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints)
	if err != nil {
		return fmt.Errorf("failed to copy prefetch file: %w", err)
	}

	// Add to manifest
	relPath := filepath.Base(destPath)
	note := fmt.Sprintf("Prefetch file - %s", w.getPrefetchNote(filepath.Base(srcPath)))
	manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), note)

	return nil
}

// getPrefetchNote generates a descriptive note for a prefetch file.
func (w *WinPrefetch) getPrefetchNote(filename string) string {
	// Prefetch files have format: APPNAME-HASH.pf
	if strings.Contains(filename, "-") && strings.HasSuffix(strings.ToLower(filename), ".pf") {
		parts := strings.Split(filename, "-")
		if len(parts) >= 2 {
			appName := parts[0]
			return fmt.Sprintf("Application: %s", appName)
		}
	}
	return "Unknown prefetch format"
}