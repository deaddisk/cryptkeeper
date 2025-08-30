//go:build windows

package win_signatures

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinSignatures represents the file signatures collection module.
type WinSignatures struct{}

// NewWinSignatures creates a new file signatures collection module.
func NewWinSignatures() *WinSignatures {
	return &WinSignatures{}
}

// Name returns the module's identifier.
func (w *WinSignatures) Name() string {
	return "windows/signatures"
}

// Collect gathers file signatures and digital certificate information.
func (w *WinSignatures) Collect(ctx context.Context, outDir string) error {
	// Create the windows/signatures subdirectory
	signaturesDir := filepath.Join(outDir, "windows", "signatures")
	if err := winutil.EnsureDir(signaturesDir); err != nil {
		return fmt.Errorf("failed to create signatures directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewSignatureManifest(hostname)

	// Collect file signatures
	if err := w.collectFileSignatures(ctx, signaturesDir, manifest); err != nil {
		manifest.AddError("file_signatures", fmt.Sprintf("Failed to collect file signatures: %v", err))
	}

	// Collect digital certificates
	if err := w.collectDigitalCertificates(ctx, signaturesDir, manifest); err != nil {
		manifest.AddError("digital_certificates", fmt.Sprintf("Failed to collect digital certificates: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(signaturesDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectFileSignatures collects file signature information from system executables.
func (w *WinSignatures) collectFileSignatures(ctx context.Context, outDir string, manifest *SignatureManifest) error {
	outputPath := filepath.Join(outDir, "file_signatures.txt")

	output := "File Signatures and Digital Signature Information:\n\n"
	output += "Note: This scan checks digital signatures of key system executables.\n\n"

	// Get system drive
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	// Key system directories to scan for signed executables
	scanDirs := []string{
		systemDrive + "\\Windows\\System32",
		systemDrive + "\\Windows\\SysWOW64",
		systemDrive + "\\Program Files",
		systemDrive + "\\Program Files (x86)",
	}

	signedCount := 0

	for _, dir := range scanDirs {
		output += fmt.Sprintf("=== Scanning %s for Digitally Signed Files ===\n", dir)
		
		// Use PowerShell to check signatures of executable files
		psScript := fmt.Sprintf(`
		Get-ChildItem -Path "%s" -Filter "*.exe" -ErrorAction SilentlyContinue | 
		Select-Object -First 20 | 
		ForEach-Object { 
			try {
				$sig = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction SilentlyContinue
				if ($sig -and $sig.Status -ne "NotSigned") {
					Write-Output "$($_.Name): $($sig.Status) - $($sig.SignerCertificate.Subject)"
				}
			} catch {}
		}`, dir)
		
		psCmd := []string{"-Command", psScript}
		if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
			resultStr := string(result)
			if len(strings.TrimSpace(resultStr)) > 0 {
				output += resultStr
				signedCount += strings.Count(resultStr, ".exe:")
			} else {
				output += "No signed executables found or access denied.\n"
			}
		} else {
			output += fmt.Sprintf("Error scanning %s: %v\n", dir, err)
		}
		output += "\n"
	}

	manifest.SetSignedFilesFound(signedCount)

	// Check signatures of critical system files
	output += "=== Critical System File Signatures ===\n"
	criticalFiles := []string{
		systemDrive + "\\Windows\\System32\\kernel32.dll",
		systemDrive + "\\Windows\\System32\\ntdll.dll", 
		systemDrive + "\\Windows\\System32\\user32.dll",
		systemDrive + "\\Windows\\System32\\advapi32.dll",
		systemDrive + "\\Windows\\explorer.exe",
		systemDrive + "\\Windows\\System32\\winlogon.exe",
		systemDrive + "\\Windows\\System32\\lsass.exe",
	}

	for _, file := range criticalFiles {
		if _, err := os.Stat(file); err == nil {
			psScript := fmt.Sprintf(`
			$sig = Get-AuthenticodeSignature -FilePath "%s" -ErrorAction SilentlyContinue
			Write-Output "%s: Status=$($sig.Status), Subject=$($sig.SignerCertificate.Subject)"`, file, filepath.Base(file))
			
			psCmd := []string{"-Command", psScript}
			if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
				output += string(result)
			} else {
				output += fmt.Sprintf("%s: Error checking signature - %v\n", filepath.Base(file), err)
			}
		}
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write file signatures: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			note := fmt.Sprintf("File signature verification results (%d signed files found)", signedCount)
			manifest.AddItem("file_signatures.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "signatures", note)
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectDigitalCertificates collects digital certificate store information.
func (w *WinSignatures) collectDigitalCertificates(ctx context.Context, outDir string, manifest *SignatureManifest) error {
	outputPath := filepath.Join(outDir, "digital_certificates.txt")

	output := "Digital Certificate Store Information:\n\n"

	// Get certificates from various certificate stores
	output += "=== Local Machine Certificate Stores ===\n"
	certStores := []string{
		"Root",
		"CA", 
		"My",
		"TrustedPublisher",
		"Disallowed",
	}

	for _, store := range certStores {
		output += fmt.Sprintf("--- %s Store ---\n", store)
		
		psScript := fmt.Sprintf(`
		Get-ChildItem -Path "Cert:\\LocalMachine\\%s" -ErrorAction SilentlyContinue | 
		Select-Object -First 10 Subject, Issuer, NotAfter, Thumbprint | 
		Format-Table -AutoSize`, store)
		
		psCmd := []string{"-Command", psScript}
		if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
			output += string(result)
		} else {
			output += fmt.Sprintf("Error accessing %s store: %v\n", store, err)
		}
		output += "\n"
	}

	// Get current user certificate stores
	output += "=== Current User Certificate Stores ===\n"
	for _, store := range []string{"My", "Root", "CA"} {
		output += fmt.Sprintf("--- Current User %s Store ---\n", store)
		
		psScript := fmt.Sprintf(`
		Get-ChildItem -Path "Cert:\\CurrentUser\\%s" -ErrorAction SilentlyContinue | 
		Select-Object -First 5 Subject, Issuer, NotAfter, Thumbprint | 
		Format-Table -AutoSize`, store)
		
		psCmd := []string{"-Command", psScript}
		if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
			output += string(result)
		} else {
			output += fmt.Sprintf("Error accessing current user %s store: %v\n", store, err)
		}
		output += "\n"
	}

	// Get certificate validation information
	output += "=== Certificate Chain Validation ===\n"
	chainScript := `
	$rootStore = Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction SilentlyContinue | Select-Object -First 5
	foreach ($cert in $rootStore) {
		Write-Output "Root CA: $($cert.Subject)"
		Write-Output "  Valid Until: $($cert.NotAfter)"
		Write-Output "  Serial: $($cert.SerialNumber)"
		Write-Output ""
	}`
	
	chainCmd := []string{"-Command", chainScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", chainCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting certificate chain info: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write digital certificates: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("digital_certificates.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "certificates", "Digital certificate store information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}