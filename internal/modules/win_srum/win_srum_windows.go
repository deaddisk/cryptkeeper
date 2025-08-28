//go:build windows

package win_srum

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinSRUM represents the Windows SRUM collection module.
type WinSRUM struct{}

// NewWinSRUM creates a new Windows SRUM collection module.
func NewWinSRUM() *WinSRUM {
	return &WinSRUM{}
}

// Name returns the module's identifier.
func (w *WinSRUM) Name() string {
	return "windows/srum"
}

// Collect copies Windows SRUM database files and creates a manifest.
func (w *WinSRUM) Collect(ctx context.Context, outDir string) error {
	// Create the windows/srum subdirectory
	srumDir := filepath.Join(outDir, "windows", "srum")
	if err := winutil.EnsureDir(srumDir); err != nil {
		return fmt.Errorf("failed to create srum directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewSRUMManifest(hostname)

	// Initialize size constraints
	constraints := winutil.NewSizeConstraints()

	// Get system paths
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}

	// Collect SRUM database files from System32\sru\
	srumSourceDir := filepath.Join(systemRoot, "System32", "sru")
	if err := w.collectSRUMFiles(ctx, srumSourceDir, srumDir, manifest, constraints); err != nil {
		manifest.AddError("srum_directory", fmt.Sprintf("Failed to collect SRUM files: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(srumDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectSRUMFiles collects SRUM database files from the source directory.
func (w *WinSRUM) collectSRUMFiles(ctx context.Context, sourceDir, outDir string, manifest *SRUMManifest, constraints *winutil.SizeConstraints) error {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return fmt.Errorf("failed to read SRUM directory: %w", err)
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
		
		// Only collect SRUM database files (.dat extension)
		if !w.isSRUMFile(filename) {
			continue
		}

		manifest.IncrementTotalFiles()

		srcPath := filepath.Join(sourceDir, filename)
		destPath := filepath.Join(outDir, filename)

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

		// Determine file type and generate note
		fileType, note := w.classifyFile(filename)

		// Add to manifest
		manifest.AddItem(filename, size, sha256Hex, truncated, stat.ModTime(), fileType, note)
	}

	return nil
}

// isSRUMFile determines if a file is a SRUM database file.
func (w *WinSRUM) isSRUMFile(filename string) bool {
	lowerFilename := strings.ToLower(filename)
	
	// SRUM database files are .dat files
	if !strings.HasSuffix(lowerFilename, ".dat") {
		return false
	}

	// Common SRUM files include:
	// SRUDB.dat - main database
	// SRU*.dat - transaction logs and other database files
	return strings.HasPrefix(lowerFilename, "sru")
}

// classifyFile determines the file type and generates a description.
func (w *WinSRUM) classifyFile(filename string) (fileType, note string) {
	lowerFilename := strings.ToLower(filename)
	
	switch lowerFilename {
	case "srudb.dat":
		return "database", "System Resource Usage Monitor main database (ESE format)"
	default:
		if strings.HasPrefix(lowerFilename, "sru") && strings.HasSuffix(lowerFilename, ".dat") {
			return "log", fmt.Sprintf("SRUM transaction log or auxiliary database (%s)", filename)
		}
		return "database", fmt.Sprintf("SRUM database file (%s)", filename)
	}
}