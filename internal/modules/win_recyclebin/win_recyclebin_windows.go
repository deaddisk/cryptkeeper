//go:build windows

package win_recyclebin

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

type WinRecycleBin struct{}

func NewWinRecycleBin() *WinRecycleBin {
	return &WinRecycleBin{}
}

func (w *WinRecycleBin) Name() string {
	return "windows/recyclebin"
}

func (w *WinRecycleBin) Collect(ctx context.Context, outDir string) error {
	recycleBinDir := filepath.Join(outDir, "windows", "recyclebin")
	if err := winutil.EnsureDir(recycleBinDir); err != nil {
		return fmt.Errorf("failed to create recyclebin directory: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	manifest := NewRecycleBinManifest(hostname)
	constraints := winutil.NewSizeConstraints()

	// Collect from all drives
	drives := []string{"C:", "D:", "E:", "F:", "G:", "H:"}
	for _, drive := range drives {
		recycleBinPath := filepath.Join(drive, "$Recycle.Bin")
		if _, err := os.Stat(recycleBinPath); err == nil {
			w.collectRecycleBinFromDrive(ctx, recycleBinPath, recycleBinDir, manifest, constraints, drive)
		}
	}

	manifestPath := filepath.Join(recycleBinDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

func (w *WinRecycleBin) collectRecycleBinFromDrive(ctx context.Context, recycleBinPath, outDir string, manifest *RecycleBinManifest, constraints *winutil.SizeConstraints, drive string) {
	sidDirs, err := os.ReadDir(recycleBinPath)
	if err != nil {
		manifest.AddError(recycleBinPath, fmt.Sprintf("Failed to read recycle bin directory: %v", err))
		return
	}

	for _, sidDir := range sidDirs {
		if !sidDir.IsDir() {
			continue
		}

		sidName := sidDir.Name()
		sidPath := filepath.Join(recycleBinPath, sidName)
		
		sidOutDir := filepath.Join(outDir, strings.Replace(drive, ":", "", 1), sidName)
		if err := winutil.EnsureDir(sidOutDir); err != nil {
			continue
		}

		// Collect files from this SID directory
		w.collectRecycleBinFiles(ctx, sidPath, sidOutDir, manifest, constraints, drive, sidName)
	}
}

func (w *WinRecycleBin) collectRecycleBinFiles(ctx context.Context, sidPath, sidOutDir string, manifest *RecycleBinManifest, constraints *winutil.SizeConstraints, drive, sidName string) {
	entries, err := os.ReadDir(sidPath)
	if err != nil {
		manifest.AddError(sidPath, fmt.Sprintf("Failed to read SID directory: %v", err))
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
		if !w.isRecycleBinFile(filename) {
			continue
		}

		manifest.IncrementTotalFiles()

		srcPath := filepath.Join(sidPath, filename)
		destPath := filepath.Join(sidOutDir, filename)

		stat, err := os.Stat(srcPath)
		if err != nil {
			manifest.AddError(srcPath, fmt.Sprintf("Failed to stat file: %v", err))
			continue
		}

		size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints)
		if err != nil {
			manifest.AddError(srcPath, fmt.Sprintf("Failed to copy file: %v", err))
			continue
		}

		fileType := w.classifyRecycleBinFile(filename)
		relPath := filepath.Join(strings.Replace(drive, ":", "", 1), sidName, filename)
		note := fmt.Sprintf("Recycle Bin file from drive %s, SID %s (%s)", drive, sidName, filename)

		manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), fileType, note)
	}
}

func (w *WinRecycleBin) isRecycleBinFile(filename string) bool {
	return strings.HasPrefix(filename, "$I") || strings.HasPrefix(filename, "$R")
}

func (w *WinRecycleBin) classifyRecycleBinFile(filename string) string {
	if strings.HasPrefix(filename, "$I") {
		return "info_file"
	}
	return "recycle_file"
}