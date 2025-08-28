//go:build windows

package win_bits

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinBITS represents the Windows BITS collection module.
type WinBITS struct{}

// NewWinBITS creates a new Windows BITS collection module.
func NewWinBITS() *WinBITS {
	return &WinBITS{}
}

// Name returns the module's identifier.
func (w *WinBITS) Name() string {
	return "windows/bits"
}

// Collect copies Windows BITS job queue files and creates a manifest.
func (w *WinBITS) Collect(ctx context.Context, outDir string) error {
	// Create the windows/bits subdirectory
	bitsDir := filepath.Join(outDir, "windows", "bits")
	if err := winutil.EnsureDir(bitsDir); err != nil {
		return fmt.Errorf("failed to create bits directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewBITSManifest(hostname)

	// Initialize size constraints
	constraints := winutil.NewSizeConstraints()

	// Get ProgramData path (usually C:\ProgramData)
	programData := os.Getenv("ProgramData")
	if programData == "" {
		// Fallback to common location
		systemDrive := os.Getenv("SystemDrive")
		if systemDrive == "" {
			systemDrive = "C:"
		}
		programData = filepath.Join(systemDrive, "ProgramData")
	}

	// Collect BITS files from ProgramData\Microsoft\Network\Downloader\
	bitsSourceDir := filepath.Join(programData, "Microsoft", "Network", "Downloader")
	if err := w.collectBITSFiles(ctx, bitsSourceDir, bitsDir, manifest, constraints); err != nil {
		manifest.AddError("bits_directory", fmt.Sprintf("Failed to collect BITS files: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(bitsDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectBITSFiles collects BITS job queue files from the source directory.
func (w *WinBITS) collectBITSFiles(ctx context.Context, sourceDir, outDir string, manifest *BITSManifest, constraints *winutil.SizeConstraints) error {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return fmt.Errorf("failed to read BITS directory: %w", err)
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
		
		// Only collect BITS job queue files (qmgr*.dat)
		if !w.isBITSFile(filename) {
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

// isBITSFile determines if a file is a BITS job queue file.
func (w *WinBITS) isBITSFile(filename string) bool {
	lowerFilename := strings.ToLower(filename)
	
	// BITS job queue files follow pattern qmgr*.dat
	return strings.HasPrefix(lowerFilename, "qmgr") && strings.HasSuffix(lowerFilename, ".dat")
}

// classifyFile determines the file type and generates a description.
func (w *WinBITS) classifyFile(filename string) (fileType, note string) {
	lowerFilename := strings.ToLower(filename)
	
	switch lowerFilename {
	case "qmgr0.dat":
		return "queue", "BITS primary job queue database"
	case "qmgr1.dat":
		return "queue", "BITS secondary job queue database"
	default:
		if strings.HasPrefix(lowerFilename, "qmgr") && strings.HasSuffix(lowerFilename, ".dat") {
			return "job", fmt.Sprintf("BITS job queue database (%s)", filename)
		}
		return "queue", fmt.Sprintf("BITS database file (%s)", filename)
	}
}