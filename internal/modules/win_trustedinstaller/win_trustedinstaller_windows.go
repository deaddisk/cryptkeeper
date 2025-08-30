//go:build windows

package win_trustedinstaller

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinTrustedInstaller represents the TrustedInstaller collection module.
type WinTrustedInstaller struct{}

// NewWinTrustedInstaller creates a new TrustedInstaller collection module.
func NewWinTrustedInstaller() *WinTrustedInstaller {
	return &WinTrustedInstaller{}
}

// Name returns the module's identifier.
func (w *WinTrustedInstaller) Name() string {
	return "windows/trustedinstaller"
}

// Collect gathers TrustedInstaller and system integrity information.
func (w *WinTrustedInstaller) Collect(ctx context.Context, outDir string) error {
	// Create the windows/trustedinstaller subdirectory
	tiDir := filepath.Join(outDir, "windows", "trustedinstaller")
	if err := winutil.EnsureDir(tiDir); err != nil {
		return fmt.Errorf("failed to create trustedinstaller directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewTrustedInstallerManifest(hostname)

	// Collect TrustedInstaller information
	if err := w.collectTrustedInstallerInfo(ctx, tiDir, manifest); err != nil {
		manifest.AddError("trusted_installer", fmt.Sprintf("Failed to collect TrustedInstaller info: %v", err))
	}

	// Collect system integrity checks
	if err := w.collectSystemIntegrity(ctx, tiDir, manifest); err != nil {
		manifest.AddError("system_integrity", fmt.Sprintf("Failed to collect system integrity: %v", err))
	}

	// Collect Windows File Protection information
	if err := w.collectWFPInfo(ctx, tiDir, manifest); err != nil {
		manifest.AddError("wfp_info", fmt.Sprintf("Failed to collect WFP info: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(tiDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectTrustedInstallerInfo collects TrustedInstaller service and ownership information.
func (w *WinTrustedInstaller) collectTrustedInstallerInfo(ctx context.Context, outDir string, manifest *TrustedInstallerManifest) error {
	outputPath := filepath.Join(outDir, "trusted_installer.txt")

	output := "TrustedInstaller Service and Ownership Information:\n\n"

	// Get TrustedInstaller service information
	output += "=== TrustedInstaller Service ===\n"
	tiServiceCmd := []string{"/C", "sc query TrustedInstaller"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", tiServiceCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error querying TrustedInstaller service: %v\n", err)
	}
	output += "\n"

	// Get detailed service configuration
	output += "=== TrustedInstaller Service Configuration ===\n"
	tiConfigCmd := []string{"/C", "sc qc TrustedInstaller"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", tiConfigCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting TrustedInstaller config: %v\n", err)
	}
	output += "\n"

	// Check file ownership of critical system files
	output += "=== Critical System File Ownership ===\n"
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	criticalFiles := []string{
		systemDrive + "\\Windows\\System32\\kernel32.dll",
		systemDrive + "\\Windows\\System32\\ntdll.dll", 
		systemDrive + "\\Windows\\System32\\user32.dll",
		systemDrive + "\\Windows\\System32\\winlogon.exe",
		systemDrive + "\\Windows\\explorer.exe",
	}

	for _, file := range criticalFiles {
		if _, err := os.Stat(file); err == nil {
			output += fmt.Sprintf("--- %s ---\n", filepath.Base(file))
			
			// Get file ownership using icacls
			icaclsCmd := []string{"/C", fmt.Sprintf("icacls \"%s\" | findstr /i \"NT SERVICE\\TrustedInstaller\"", file)}
			if result, err := winutil.RunCommandWithOutput(ctx, "cmd", icaclsCmd); err == nil {
				if len(strings.TrimSpace(string(result))) > 0 {
					output += "✓ Owned by TrustedInstaller\n"
				} else {
					output += "⚠ NOT owned by TrustedInstaller\n"
				}
			} else {
				output += fmt.Sprintf("Error checking ownership: %v\n", err)
			}
		}
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write trusted installer info: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("trusted_installer.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "trusted_installer", "TrustedInstaller service and file ownership information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectSystemIntegrity collects system integrity and file verification information.
func (w *WinTrustedInstaller) collectSystemIntegrity(ctx context.Context, outDir string, manifest *TrustedInstallerManifest) error {
	outputPath := filepath.Join(outDir, "system_integrity.txt")

	output := "System Integrity and File Verification:\n\n"
	output += "Note: Running comprehensive system integrity checks may take time.\n"
	output += "This collection performs quick integrity verification of critical components.\n\n"

	violationCount := 0

	// Run System File Checker scan
	output += "=== System File Checker (SFC) Status ===\n"
	output += "Checking SFC scan history...\n"
	
	// Check CBS log for recent SFC activity
	cbsLogPath := os.Getenv("SystemRoot") + "\\Logs\\CBS\\CBS.log"
	if _, err := os.Stat(cbsLogPath); err == nil {
		// Get last few lines of CBS log
		tailCmd := []string{"/C", fmt.Sprintf("powershell \"Get-Content '%s' | Select-Object -Last 20\"", cbsLogPath)}
		if result, err := winutil.RunCommandWithOutput(ctx, "cmd", tailCmd); err == nil {
			output += string(result)
		} else {
			output += fmt.Sprintf("Error reading CBS log: %v\n", err)
		}
	} else {
		output += "CBS.log not found - no recent SFC activity\n"
	}
	output += "\n"

	// Check Windows Resource Protection status
	output += "=== Windows Resource Protection Status ===\n"
	// Note: Full sfc /scannow would take too long, so we check configuration
	
	// Get WRP configuration from registry
	wrpKey := "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
	wrpCmd := []string{"query", wrpKey, "/v", "SFCDisable"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", wrpCmd); err == nil {
		output += "WRP Registry Configuration:\n"
		output += string(result)
	} else {
		output += "WRP appears to be enabled (default configuration)\n"
	}
	output += "\n"

	// Check DISM component store health (quick check)
	output += "=== Component Store Health (DISM) ===\n"
	output += "Running quick component store scan...\n"
	dismCmd := []string{"/C", "DISM /Online /Cleanup-Image /CheckHealth"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", dismCmd); err == nil {
		resultStr := string(result)
		output += resultStr
		if strings.Contains(resultStr, "corrupted") || strings.Contains(resultStr, "errors") {
			violationCount++
		}
	} else {
		output += fmt.Sprintf("Error running DISM CheckHealth: %v\n", err)
	}
	output += "\n"

	// Check Windows Defender integrity
	output += "=== Windows Defender Integrity ===\n"
	defenderCmd := []string{"/C", "powershell \"Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled, DefenderSignaturesOutOfDate\""}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", defenderCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error checking Defender status: %v\n", err)
	}

	manifest.SetIntegrityViolations(violationCount)

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write system integrity: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			note := fmt.Sprintf("System integrity verification results (%d violations found)", violationCount)
			manifest.AddItem("system_integrity.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "system_integrity", note)
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectWFPInfo collects Windows File Protection and Resource Protection information.
func (w *WinTrustedInstaller) collectWFPInfo(ctx context.Context, outDir string, manifest *TrustedInstallerManifest) error {
	outputPath := filepath.Join(outDir, "wfp_info.txt")

	output := "Windows File Protection and Resource Protection Information:\n\n"

	// Get protected files list from registry
	output += "=== Windows Resource Protection Configuration ===\n"
	wrpExclusionsKey := "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SFC"
	wrpCmd := []string{"query", wrpExclusionsKey, "/s"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", wrpCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error querying WRP config: %v\n", err)
	}
	output += "\n"

	// Get system file locations from registry
	output += "=== System File Locations ===\n"
	systemFileKey := "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRoot"
	systemFileCmd := []string{"query", systemFileKey}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", systemFileCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error querying system file locations: %v\n", err)
	}
	output += "\n"

	// Check Windows servicing status
	output += "=== Windows Servicing Status ===\n"
	servicingKey := "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing"
	servicingCmd := []string{"query", servicingKey, "/s"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", servicingCmd); err == nil {
		// Limit output size by truncating if too long
		resultStr := string(result)
		if len(resultStr) > 5000 {
			output += resultStr[:5000] + "\n... (truncated)\n"
		} else {
			output += resultStr
		}
	} else {
		output += fmt.Sprintf("Error querying servicing status: %v\n", err)
	}
	output += "\n"

	// Get Windows Update Agent information
	output += "=== Windows Update Agent Status ===\n"
	wuaCmd := []string{"/C", "powershell \"Get-Service -Name wuauserv | Format-List *\""}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", wuaCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting Windows Update Agent status: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write WFP info: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("wfp_info.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "wfp_info", "Windows File Protection and Resource Protection information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}