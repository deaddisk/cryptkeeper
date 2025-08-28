//go:build windows

package win_tasks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinTasks represents the Windows scheduled tasks collection module.
type WinTasks struct{}

// NewWinTasks creates a new Windows scheduled tasks collection module.
func NewWinTasks() *WinTasks {
	return &WinTasks{}
}

// Name returns the module's identifier.
func (w *WinTasks) Name() string {
	return "windows/tasks"
}

// Collect copies Windows scheduled task files and creates a manifest.
func (w *WinTasks) Collect(ctx context.Context, outDir string) error {
	// Create the windows/tasks subdirectory
	tasksDir := filepath.Join(outDir, "windows", "tasks")
	if err := winutil.EnsureDir(tasksDir); err != nil {
		return fmt.Errorf("failed to create tasks directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewTaskManifest(hostname)

	// Initialize size constraints
	constraints := winutil.NewSizeConstraints()

	// Get system paths
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}

	// Collect scheduled task files from System32\Tasks\
	tasksSourceDir := filepath.Join(systemRoot, "System32", "Tasks")
	if err := w.collectTaskFiles(ctx, tasksSourceDir, tasksDir, "", manifest, constraints); err != nil {
		manifest.AddError("tasks_directory", fmt.Sprintf("Failed to collect scheduled tasks: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(tasksDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectTaskFiles recursively collects scheduled task files while preserving directory structure.
func (w *WinTasks) collectTaskFiles(ctx context.Context, sourceDir, outDir, relativePath string, manifest *TaskManifest, constraints *winutil.SizeConstraints) error {
	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return fmt.Errorf("failed to read tasks directory: %w", err)
	}

	manifest.IncrementDirectoriesScanned()

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		entryName := entry.Name()
		srcPath := filepath.Join(sourceDir, entryName)
		
		// Build relative path for manifest tracking
		var currentRelPath string
		if relativePath == "" {
			currentRelPath = entryName
		} else {
			currentRelPath = filepath.Join(relativePath, entryName)
		}

		if entry.IsDir() {
			// Create subdirectory in output and recurse
			subOutDir := filepath.Join(outDir, entryName)
			if err := winutil.EnsureDir(subOutDir); err != nil {
				manifest.AddError(srcPath, fmt.Sprintf("Failed to create subdirectory: %v", err))
				continue
			}
			
			if err := w.collectTaskFiles(ctx, srcPath, subOutDir, currentRelPath, manifest, constraints); err != nil {
				manifest.AddError(srcPath, fmt.Sprintf("Failed to process subdirectory: %v", err))
			}
			continue
		}

		// Only collect XML files (scheduled tasks are XML format)
		if !w.isTaskFile(entryName) {
			continue
		}

		manifest.IncrementTotalFiles()

		// Create destination path preserving directory structure
		destPath := filepath.Join(outDir, entryName)

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

		// Generate description
		note := w.generateTaskNote(entryName, currentRelPath)

		// Add to manifest with preserved path
		manifest.AddItem(entryName, size, sha256Hex, truncated, stat.ModTime(), currentRelPath, note)
	}

	return nil
}

// isTaskFile determines if a file is a scheduled task file.
func (w *WinTasks) isTaskFile(filename string) bool {
	lowerFilename := strings.ToLower(filename)
	
	// Scheduled task files are XML files
	// Skip some system files that aren't actual tasks
	if strings.HasPrefix(lowerFilename, "desktop.ini") {
		return false
	}
	
	// Accept XML files (most tasks) and files without extension (some system tasks)
	return strings.HasSuffix(lowerFilename, ".xml") || !strings.Contains(filename, ".")
}

// generateTaskNote creates a descriptive note for task files.
func (w *WinTasks) generateTaskNote(filename, taskPath string) string {
	if strings.HasSuffix(strings.ToLower(filename), ".xml") {
		return fmt.Sprintf("Scheduled task XML definition (%s)", taskPath)
	}
	return fmt.Sprintf("Scheduled task definition (%s)", taskPath)
}