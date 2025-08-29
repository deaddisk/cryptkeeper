//go:build windows

package win_iis

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

type WinIIS struct{}

func NewWinIIS() *WinIIS {
	return &WinIIS{}
}

func (w *WinIIS) Name() string {
	return "windows/iis"
}

func (w *WinIIS) Collect(ctx context.Context, outDir string) error {
	iisDir := filepath.Join(outDir, "windows", "iis")
	if err := winutil.EnsureDir(iisDir); err != nil {
		return fmt.Errorf("failed to create iis directory: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	manifest := NewIISManifest(hostname)
	constraints := winutil.NewSizeConstraints()

	// Check if IIS is installed by looking for inetpub
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	inetpubPath := filepath.Join(systemDrive, "inetpub")
	if _, err := os.Stat(inetpubPath); err != nil {
		// IIS not installed - create a note file
		notePath := filepath.Join(iisDir, "IIS_NOT_INSTALLED.txt")
		noteContent := "IIS does not appear to be installed on this system (no inetpub directory found)"
		if err := os.WriteFile(notePath, []byte(noteContent), 0644); err == nil {
			stat, _ := os.Stat(notePath)
			manifest.AddItem("IIS_NOT_INSTALLED.txt", int64(len(noteContent)), "", false, stat.ModTime(), "web_log", "IIS installation status note")
		}
	} else {
		// Collect IIS logs
		logsPath := filepath.Join(inetpubPath, "logs", "LogFiles")
		if err := w.collectIISLogs(ctx, logsPath, iisDir, manifest, constraints); err != nil {
			manifest.AddError("iis_logs", fmt.Sprintf("Failed to collect IIS logs: %v", err))
		}
	}

	manifestPath := filepath.Join(iisDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

func (w *WinIIS) collectIISLogs(ctx context.Context, logsPath, outDir string, manifest *IISManifest, constraints *winutil.SizeConstraints) error {
	return filepath.WalkDir(logsPath, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to access path: %v", err))
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			return nil
		}

		filename := d.Name()
		if !w.isIISLogFile(filename) {
			return nil
		}

		manifest.IncrementTotalFiles()

		// Get relative path from logs directory
		relPath, err := filepath.Rel(logsPath, path)
		if err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to get relative path: %v", err))
			return nil
		}

		// Create destination path
		destPath := filepath.Join(outDir, "logs", relPath)
		
		// Ensure destination directory exists
		destDir := filepath.Dir(destPath)
		if err := winutil.EnsureDir(destDir); err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to create destination directory: %v", err))
			return nil
		}

		// Get file info
		stat, err := os.Stat(path)
		if err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to stat file: %v", err))
			return nil
		}

		// Use tail copy for large log files with size constraints
		size, sha256Hex, truncated, err := winutil.SmartCopy(path, destPath, constraints)
		if err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to copy file: %v", err))
			return nil
		}

		// Generate manifest path relative to iis directory
		manifestRelPath := filepath.Join("logs", relPath)
		note := fmt.Sprintf("IIS web server log file (%s)", filename)

		manifest.AddItem(manifestRelPath, size, sha256Hex, truncated, stat.ModTime(), "web_log", note)

		return nil
	})
}

func (w *WinIIS) isIISLogFile(filename string) bool {
	lowerFilename := strings.ToLower(filename)
	return strings.HasSuffix(lowerFilename, ".log") || 
		   strings.HasPrefix(lowerFilename, "ex") ||
		   strings.HasPrefix(lowerFilename, "u_ex")
}