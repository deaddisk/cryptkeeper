//go:build windows

package win_certificates

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinCertificates represents the certificates collection module.
type WinCertificates struct{}

// NewWinCertificates creates a new certificates collection module.
func NewWinCertificates() *WinCertificates {
	return &WinCertificates{}
}

// Name returns the module's identifier.
func (w *WinCertificates) Name() string {
	return "windows/certificates"
}

// Collect gathers certificate store and PKI configuration information.
func (w *WinCertificates) Collect(ctx context.Context, outDir string) error {
	// Create the windows/certificates subdirectory
	certificatesDir := filepath.Join(outDir, "windows", "certificates")
	if err := winutil.EnsureDir(certificatesDir); err != nil {
		return fmt.Errorf("failed to create certificates directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewCertificateManifest(hostname)

	// Collect certificate stores
	if err := w.collectCertificateStores(ctx, certificatesDir, manifest); err != nil {
		manifest.AddError("cert_stores", fmt.Sprintf("Failed to collect certificate stores: %v", err))
	}

	// Collect PKI configuration
	if err := w.collectPKIConfig(ctx, certificatesDir, manifest); err != nil {
		manifest.AddError("pki_config", fmt.Sprintf("Failed to collect PKI config: %v", err))
	}

	// Collect cryptographic policies
	if err := w.collectCryptoPolicies(ctx, certificatesDir, manifest); err != nil {
		manifest.AddError("crypto_policies", fmt.Sprintf("Failed to collect crypto policies: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(certificatesDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectCertificateStores collects comprehensive certificate store information.
func (w *WinCertificates) collectCertificateStores(ctx context.Context, outDir string, manifest *CertificateManifest) error {
	outputPath := filepath.Join(outDir, "certificate_stores.txt")

	output := "Certificate Stores Comprehensive Information:\n\n"

	certCount := 0

	// Machine certificate stores
	output += "=== Local Machine Certificate Stores ===\n"
	machineStores := []string{"Root", "CA", "My", "TrustedPublisher", "Disallowed", "TrustedPeople", "AuthRoot"}

	for _, store := range machineStores {
		output += fmt.Sprintf("--- LocalMachine\\%s ---\n", store)
		
		psScript := fmt.Sprintf(`
		$certs = Get-ChildItem -Path "Cert:\\LocalMachine\\%s" -ErrorAction SilentlyContinue
		Write-Output "Certificate Count: $($certs.Count)"
		$certs | Select-Object -First 15 | ForEach-Object {
			Write-Output "Subject: $($_.Subject)"
			Write-Output "Issuer: $($_.Issuer)"
			Write-Output "Valid: $($_.NotBefore) to $($_.NotAfter)"
			Write-Output "Thumbprint: $($_.Thumbprint)"
			Write-Output "---"
		}`, store)
		
		psCmd := []string{"-Command", psScript}
		if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
			resultStr := string(result)
			output += resultStr
			certCount += strings.Count(resultStr, "Thumbprint:")
		} else {
			output += fmt.Sprintf("Error accessing %s store: %v\n", store, err)
		}
		output += "\n"
	}

	// Current user certificate stores
	output += "=== Current User Certificate Stores ===\n"
	userStores := []string{"My", "Root", "CA", "TrustedPublisher"}

	for _, store := range userStores {
		output += fmt.Sprintf("--- CurrentUser\\%s ---\n", store)
		
		psScript := fmt.Sprintf(`
		$certs = Get-ChildItem -Path "Cert:\\CurrentUser\\%s" -ErrorAction SilentlyContinue
		Write-Output "Certificate Count: $($certs.Count)"
		$certs | Select-Object -First 10 | ForEach-Object {
			Write-Output "Subject: $($_.Subject)"
			Write-Output "Issuer: $($_.Issuer)"
			Write-Output "Valid: $($_.NotBefore) to $($_.NotAfter)"
			Write-Output "Thumbprint: $($_.Thumbprint)"
			Write-Output "---"
		}`, store)
		
		psCmd := []string{"-Command", psScript}
		if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
			resultStr := string(result)
			output += resultStr
			certCount += strings.Count(resultStr, "Thumbprint:")
		} else {
			output += fmt.Sprintf("Error accessing CurrentUser %s store: %v\n", store, err)
		}
		output += "\n"
	}

	manifest.SetCertificatesFound(certCount)

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write certificate stores: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			note := fmt.Sprintf("Certificate stores information (%d certificates found)", certCount)
			manifest.AddItem("certificate_stores.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "cert_stores", note)
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectPKIConfig collects PKI configuration and certificate services information.
func (w *WinCertificates) collectPKIConfig(ctx context.Context, outDir string, manifest *CertificateManifest) error {
	outputPath := filepath.Join(outDir, "pki_config.txt")

	output := "PKI Configuration and Certificate Services:\n\n"

	// Certificate services configuration
	output += "=== Certificate Services Configuration ===\n"
	certSrvKey := "HKLM\\SYSTEM\\CurrentControlSet\\Services\\CertSvc"
	certSrvCmd := []string{"query", certSrvKey, "/s"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", certSrvCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Certificate Services not installed or error: %v\n", err)
	}
	output += "\n"

	// Cryptographic service providers
	output += "=== Cryptographic Service Providers ===\n"
	cspKey := "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\Defaults\\Provider"
	cspCmd := []string{"query", cspKey, "/s"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", cspCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error querying CSP: %v\n", err)
	}
	output += "\n"

	// Certificate enrollment configuration
	output += "=== Certificate Enrollment Configuration ===\n"
	enrollKey := "HKLM\\SOFTWARE\\Microsoft\\Cryptography\\AutoEnrollment"
	enrollCmd := []string{"query", enrollKey, "/s"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", enrollCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error querying enrollment config: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write PKI config: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("pki_config.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "pki_config", "PKI configuration and certificate services")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectCryptoPolicies collects cryptographic policies and algorithm configuration.
func (w *WinCertificates) collectCryptoPolicies(ctx context.Context, outDir string, manifest *CertificateManifest) error {
	outputPath := filepath.Join(outDir, "crypto_policies.txt")

	output := "Cryptographic Policies and Algorithm Configuration:\n\n"

	// System cryptography policies
	output += "=== System Cryptography Policies ===\n"
	cryptoKey := "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography"
	cryptoCmd := []string{"query", cryptoKey, "/s"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", cryptoCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("No cryptography policies found or error: %v\n", err)
	}
	output += "\n"

	// TLS/SSL configuration
	output += "=== TLS/SSL Configuration ===\n"
	tlsKey := "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL"
	tlsCmd := []string{"query", tlsKey, "/s"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", tlsCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error querying TLS config: %v\n", err)
	}
	output += "\n"

	// ECC curve configuration
	output += "=== ECC Curve Configuration ===\n"
	eccKey := "HKLM\\SOFTWARE\\Policies\\Microsoft\\Cryptography\\Configuration\\SSL\\00010002"
	eccCmd := []string{"query", eccKey, "/s"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", eccCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("No ECC curve policies found or error: %v\n", err)
	}
	output += "\n"

	// FIPS mode configuration
	output += "=== FIPS Mode Configuration ===\n"
	fipsKey := "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\FipsAlgorithmPolicy"
	fipsCmd := []string{"query", fipsKey}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", fipsCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("FIPS configuration not found or error: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write crypto policies: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("crypto_policies.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "crypto_policies", "Cryptographic policies and algorithm configuration")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}