//go:build windows

package win_mft

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinMFT represents the NTFS Master File Table collection module.
type WinMFT struct{}

// NewWinMFT creates a new NTFS Master File Table collection module.
func NewWinMFT() *WinMFT {
	return &WinMFT{}
}

// Name returns the module's identifier.
func (w *WinMFT) Name() string {
	return "windows/mft"
}

// Collect gathers NTFS Master File Table records and metadata.
func (w *WinMFT) Collect(ctx context.Context, outDir string) error {
	// Create the windows/mft subdirectory
	mftDir := filepath.Join(outDir, "windows", "mft")
	if err := winutil.EnsureDir(mftDir); err != nil {
		return fmt.Errorf("failed to create mft directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewMFTManifest(hostname)

	// Collect NTFS volumes information
	if err := w.collectVolumeInfo(ctx, mftDir, manifest); err != nil {
		manifest.AddError("volume_info", fmt.Sprintf("Failed to collect volume info: %v", err))
	}

	// Collect MFT metadata (not raw MFT due to size and privilege requirements)
	if err := w.collectMFTMetadata(ctx, mftDir, manifest); err != nil {
		manifest.AddError("mft_metadata", fmt.Sprintf("Failed to collect MFT metadata: %v", err))
	}

	// Collect file system information
	if err := w.collectFileSystemInfo(ctx, mftDir, manifest); err != nil {
		manifest.AddError("filesystem_info", fmt.Sprintf("Failed to collect filesystem info: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(mftDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectVolumeInfo collects information about NTFS volumes.
func (w *WinMFT) collectVolumeInfo(ctx context.Context, outDir string, manifest *MFTManifest) error {
	outputPath := filepath.Join(outDir, "volume_info.txt")

	// Use fsutil to get volume information
	output := "NTFS Volume Information:\n\n"

	// Get volume information using fsutil
	volumeCmd := []string{"fsinfo", "drives"}
	if result, err := winutil.RunCommandWithOutput(ctx, "fsutil", volumeCmd); err == nil {
		output += "=== Available Drives ===\n"
		output += string(result)
		output += "\n\n"
		
		// Parse drives and get detailed info for each NTFS volume
		drives := w.parseDriversFromFsutil(string(result))
		for _, drive := range drives {
			output += fmt.Sprintf("=== Volume %s Details ===\n", drive)
			
			// Get volume info
			volInfoCmd := []string{"fsinfo", "volumeinfo", drive}
			if volResult, err := winutil.RunCommandWithOutput(ctx, "fsutil", volInfoCmd); err == nil {
				output += string(volResult)
				manifest.AddProcessedVolume(drive)
			} else {
				output += fmt.Sprintf("Error getting volume info for %s: %v\n", drive, err)
			}
			output += "\n"

			// Get NTFS info if it's an NTFS volume
			ntfsInfoCmd := []string{"fsinfo", "ntfsinfo", drive}
			if ntfsResult, err := winutil.RunCommandWithOutput(ctx, "fsutil", ntfsInfoCmd); err == nil {
				output += fmt.Sprintf("=== NTFS Info for %s ===\n", drive)
				output += string(ntfsResult)
				output += "\n"
			}
		}
	} else {
		output += fmt.Sprintf("Error running fsutil drives: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write volume info: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("volume_info.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "mft_parsed", "NTFS volume and filesystem information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectMFTMetadata collects metadata about the MFT without requiring raw disk access.
func (w *WinMFT) collectMFTMetadata(ctx context.Context, outDir string, manifest *MFTManifest) error {
	outputPath := filepath.Join(outDir, "mft_metadata.txt")

	output := "MFT Metadata Collection:\n\n"
	output += "Note: Raw MFT extraction requires administrator privileges and specialized tools.\n"
	output += "This collection focuses on MFT-related metadata accessible via standard APIs.\n\n"

	// Use dir command to get file metadata from root directories
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	// Get detailed directory listings for key system directories
	keyDirs := []string{
		systemDrive + "\\",
		systemDrive + "\\Windows",
		systemDrive + "\\Windows\\System32",
		systemDrive + "\\Program Files",
		systemDrive + "\\Users",
	}

	for _, dir := range keyDirs {
		output += fmt.Sprintf("=== Directory Metadata: %s ===\n", dir)
		
		// Use dir with detailed attributes
		dirCmd := []string{"/C", fmt.Sprintf("dir \"%s\" /A /T:C /Q", dir)}
		if result, err := winutil.RunCommandWithOutput(ctx, "cmd", dirCmd); err == nil {
			output += string(result)
		} else {
			output += fmt.Sprintf("Error listing directory %s: %v\n", dir, err)
		}
		output += "\n"
	}

	// Get file allocation table info
	output += "=== File Allocation Information ===\n"
	fsstatCmd := []string{"/C", fmt.Sprintf("fsutil fsinfo statistics %s", systemDrive)}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", fsstatCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting filesystem statistics: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write MFT metadata: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("mft_metadata.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "mft_parsed", "MFT-related metadata and file system statistics")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectFileSystemInfo collects general file system information.
func (w *WinMFT) collectFileSystemInfo(ctx context.Context, outDir string, manifest *MFTManifest) error {
	outputPath := filepath.Join(outDir, "filesystem_info.txt")

	output := "File System Information:\n\n"

	// Get disk usage information
	output += "=== Disk Usage ===\n"
	diskCmd := []string{"/C", "wmic logicaldisk get size,freespace,caption,filesystem,volumename"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", diskCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting disk info: %v\n", err)
	}
	output += "\n"

	// Get partition information
	output += "=== Partition Information ===\n"
	partCmd := []string{"/C", "wmic partition get size,startingoffset,type,bootable,primarypartition"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", partCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting partition info: %v\n", err)
	}
	output += "\n"

	// Get volume information
	output += "=== Volume Information ===\n"
	volCmd := []string{"/C", "wmic volume get capacity,freespace,label,filesystem,driveletter"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", volCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting volume info: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write filesystem info: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("filesystem_info.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "file_metadata", "General file system and disk information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// parseDriversFromFsutil parses drive letters from fsutil output.
func (w *WinMFT) parseDriversFromFsutil(output string) []string {
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