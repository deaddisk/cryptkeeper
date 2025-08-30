//go:build windows

package win_usn

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinUSN represents the NTFS USN Journal collection module.
type WinUSN struct{}

// NewWinUSN creates a new NTFS USN Journal collection module.
func NewWinUSN() *WinUSN {
	return &WinUSN{}
}

// Name returns the module's identifier.
func (w *WinUSN) Name() string {
	return "windows/usn"
}

// Collect gathers NTFS USN Journal information and metadata.
func (w *WinUSN) Collect(ctx context.Context, outDir string) error {
	// Create the windows/usn subdirectory
	usnDir := filepath.Join(outDir, "windows", "usn")
	if err := winutil.EnsureDir(usnDir); err != nil {
		return fmt.Errorf("failed to create usn directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewUSNManifest(hostname)

	// Collect USN Journal information
	if err := w.collectUSNJournalInfo(ctx, usnDir, manifest); err != nil {
		manifest.AddError("usn_journal_info", fmt.Sprintf("Failed to collect USN Journal info: %v", err))
	}

	// Collect change journal statistics
	if err := w.collectChangeJournalStats(ctx, usnDir, manifest); err != nil {
		manifest.AddError("change_journal_stats", fmt.Sprintf("Failed to collect change journal stats: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(usnDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectUSNJournalInfo collects USN Journal information for all NTFS volumes.
func (w *WinUSN) collectUSNJournalInfo(ctx context.Context, outDir string, manifest *USNManifest) error {
	outputPath := filepath.Join(outDir, "usn_journal_info.txt")

	output := "NTFS USN Journal Information:\n\n"
	output += "Note: USN Journal tracks file system changes on NTFS volumes.\n"
	output += "This collection gathers metadata about the journals without extracting raw records.\n\n"

	// Get available drives
	drivesCmd := []string{"fsinfo", "drives"}
	if result, err := winutil.RunCommandWithOutput(ctx, "fsutil", drivesCmd); err == nil {
		drives := w.parseDriversFromFsutil(string(result))
		
		for _, drive := range drives {
			output += fmt.Sprintf("=== USN Journal Info for %s ===\n", drive)
			manifest.AddProcessedVolume(drive)

			// Query USN Journal information
			usnQueryCmd := []string{"usn", "queryjournal", drive}
			if usnResult, err := winutil.RunCommandWithOutput(ctx, "fsutil", usnQueryCmd); err == nil {
				output += string(usnResult)
				output += "\n"
			} else {
				output += fmt.Sprintf("Error querying USN journal for %s: %v\n", drive, err)
				output += "This may indicate no USN journal exists or insufficient privileges.\n\n"
			}

			// Query USN Journal statistics
			usnStatsCmd := []string{"usn", "readdata", drive}
			if statsResult, err := winutil.RunCommandWithOutput(ctx, "fsutil", usnStatsCmd); err == nil {
				output += fmt.Sprintf("=== USN Journal Statistics for %s ===\n", drive)
				output += string(statsResult)
				output += "\n"
			} else {
				output += fmt.Sprintf("Note: Could not read USN data for %s (may require admin privileges): %v\n\n", drive, err)
			}
		}
	} else {
		output += fmt.Sprintf("Error getting drives: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write USN journal info: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("usn_journal_info.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "usn_info", "NTFS USN Journal information and statistics")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectChangeJournalStats collects change journal statistics and configuration.
func (w *WinUSN) collectChangeJournalStats(ctx context.Context, outDir string, manifest *USNManifest) error {
	outputPath := filepath.Join(outDir, "change_journal_stats.txt")

	output := "Change Journal Statistics and Configuration:\n\n"

	// Get system drive
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	// Get file system statistics which includes change journal info
	output += "=== File System Statistics ===\n"
	fsStatsCmd := []string{"fsinfo", "statistics", systemDrive}
	if result, err := winutil.RunCommandWithOutput(ctx, "fsutil", fsStatsCmd); err == nil {
		output += string(result)
		output += "\n"
	} else {
		output += fmt.Sprintf("Error getting filesystem statistics: %v\n\n", err)
	}

	// Check for recent file changes using forfiles (as a proxy for change tracking)
	output += "=== Recent File Changes (Last 7 days) ===\n"
	output += "Note: This provides a sample of recent changes as an indication of system activity.\n\n"

	// Get recent changes in system directories
	recentDirs := []string{
		systemDrive + "\\Windows\\System32",
		systemDrive + "\\Windows\\Temp",
		systemDrive + "\\Users",
	}

	for _, dir := range recentDirs {
		output += fmt.Sprintf("--- Recent changes in %s ---\n", dir)
		
		// Use forfiles to find recently modified files (last 7 days)
		forfilesCmd := []string{"/C", fmt.Sprintf("forfiles /P \"%s\" /M *.* /D -7 /C \"cmd /c echo @path @fdate @ftime\"", dir)}
		if result, err := winutil.RunCommandWithOutput(ctx, "cmd", forfilesCmd); err == nil {
			lines := strings.Split(string(result), "\n")
			// Limit output to first 20 lines to avoid excessive data
			maxLines := 20
			if len(lines) > maxLines {
				for i := 0; i < maxLines; i++ {
					output += lines[i] + "\n"
				}
				output += fmt.Sprintf("... (truncated, %d total results)\n", len(lines))
			} else {
				output += string(result)
			}
		} else {
			output += fmt.Sprintf("No recent changes found or access denied: %v\n", err)
		}
		output += "\n"
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write change journal stats: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("change_journal_stats.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "journal_metadata", "Change journal statistics and recent file activity")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// parseDriversFromFsutil parses drive letters from fsutil output.
func (w *WinUSN) parseDriversFromFsutil(output string) []string {
	var drives []string
	lines := strings.Split(output, "\n")
	
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) >= 3 && strings.HasSuffix(line, "\\") {
			// Extract drive letter (e.g., "C:\\" -> "C:")
			if drive := strings.TrimSuffix(line, "\\"); len(drive) >= 2 {
				drives = append(drives, drive)
			}
		}
	}
	
	return drives
}