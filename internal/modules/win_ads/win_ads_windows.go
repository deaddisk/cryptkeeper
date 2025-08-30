//go:build windows

package win_ads

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinADS represents the Alternate Data Streams collection module.
type WinADS struct{}

// NewWinADS creates a new Alternate Data Streams collection module.
func NewWinADS() *WinADS {
	return &WinADS{}
}

// Name returns the module's identifier.
func (w *WinADS) Name() string {
	return "windows/ads"
}

// Collect gathers Alternate Data Streams information and metadata.
func (w *WinADS) Collect(ctx context.Context, outDir string) error {
	// Create the windows/ads subdirectory
	adsDir := filepath.Join(outDir, "windows", "ads")
	if err := winutil.EnsureDir(adsDir); err != nil {
		return fmt.Errorf("failed to create ads directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewADSManifest(hostname)

	// Collect ADS information
	if err := w.collectADSInfo(ctx, adsDir, manifest); err != nil {
		manifest.AddError("ads_scan", fmt.Sprintf("Failed to collect ADS info: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(adsDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectADSInfo collects Alternate Data Streams information.
func (w *WinADS) collectADSInfo(ctx context.Context, outDir string, manifest *ADSManifest) error {
	outputPath := filepath.Join(outDir, "ads_scan.txt")

	output := "Alternate Data Streams (ADS) Information:\n\n"
	output += "Note: ADS can be used to hide data within NTFS file systems.\n"
	output += "This scan looks for common locations where ADS might be found.\n\n"

	// Get system drive
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	// Scan key directories for ADS
	scanDirs := []string{
		systemDrive + "\\",
		systemDrive + "\\Windows",
		systemDrive + "\\Windows\\System32",
		systemDrive + "\\Users",
		systemDrive + "\\Temp",
		systemDrive + "\\Windows\\Temp",
	}

	streamCount := 0

	for _, dir := range scanDirs {
		output += fmt.Sprintf("=== Scanning %s for Alternate Data Streams ===\n", dir)
		
		// Use PowerShell to scan for ADS
		psScript := fmt.Sprintf(`
		Get-ChildItem -Path "%s" -Recurse -ErrorAction SilentlyContinue | 
		ForEach-Object { 
			try {
				$streams = Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object {$_.Stream -ne ":$DATA"} 
				if ($streams) {
					Write-Output "File: $($_.FullName)"
					$streams | ForEach-Object { 
						Write-Output "  Stream: $($_.Stream) (Size: $($_.Length) bytes)"
					}
				}
			} catch {}
		}`, dir)
		
		psCmd := []string{"-Command", psScript}
		if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
			resultStr := string(result)
			output += resultStr
			// Count streams found
			streamCount += strings.Count(resultStr, "Stream:")
		} else {
			output += fmt.Sprintf("Error scanning %s: %v\n", dir, err)
		}
		output += "\n"
		
		// Limit scan depth to avoid excessive processing
		// Only scan root and Windows directories deeply
		if strings.Contains(dir, "Users") {
			break
		}
	}

	manifest.SetStreamsFound(streamCount)

	// Also scan for common ADS using dir command
	output += "=== Common ADS Patterns (dir command) ===\n"
	output += "Scanning for files with Zone.Identifier (downloaded files)...\n"
	
	zoneCmd := []string{"/C", fmt.Sprintf("dir /s /a \"%s\\Users\" 2>nul | findstr Zone.Identifier", systemDrive)}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", zoneCmd); err == nil {
		if len(strings.TrimSpace(string(result))) > 0 {
			output += string(result)
		} else {
			output += "No Zone.Identifier streams found in Users directory.\n"
		}
	} else {
		output += fmt.Sprintf("Error scanning for Zone.Identifier: %v\n", err)
	}
	output += "\n"

	// Scan temp directories more thoroughly
	output += "=== Detailed Temp Directory ADS Scan ===\n"
	tempDirs := []string{
		os.Getenv("TEMP"),
		os.Getenv("TMP"),
		systemDrive + "\\Windows\\Temp",
	}

	for _, tempDir := range tempDirs {
		if tempDir != "" {
			output += fmt.Sprintf("--- Scanning %s ---\n", tempDir)
			tempScript := fmt.Sprintf(`
			if (Test-Path "%s") {
				Get-ChildItem -Path "%s" -File -ErrorAction SilentlyContinue | 
				ForEach-Object { 
					try {
						$streams = Get-Item -Path $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object {$_.Stream -ne ":$DATA"} 
						if ($streams) {
							Write-Output "$($_.Name):"
							$streams | ForEach-Object { 
								Write-Output "  $($_.Stream) ($($_.Length) bytes)"
							}
						}
					} catch {}
				}
			}`, tempDir, tempDir)
			
			tempCmd := []string{"-Command", tempScript}
			if result, err := winutil.RunCommandWithOutput(ctx, "powershell", tempCmd); err == nil {
				if len(strings.TrimSpace(string(result))) > 0 {
					output += string(result)
				} else {
					output += "No alternate data streams found.\n"
				}
			} else {
				output += fmt.Sprintf("Error scanning temp directory: %v\n", err)
			}
			output += "\n"
		}
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write ADS scan: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			note := fmt.Sprintf("Alternate Data Streams scan results (%d streams found)", streamCount)
			manifest.AddItem("ads_scan.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "ads_scan", note)
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}