//go:build windows

package win_lsa

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"cryptkeeper/internal/winutil"
)

// WinLSA represents the LSA Secrets collection module.
type WinLSA struct{}

// NewWinLSA creates a new LSA Secrets collection module.
func NewWinLSA() *WinLSA {
	return &WinLSA{}
}

// Name returns the module's identifier.
func (w *WinLSA) Name() string {
	return "windows/lsa"
}

// Collect gathers LSA Secrets and authentication-related information.
func (w *WinLSA) Collect(ctx context.Context, outDir string) error {
	// Create the windows/lsa subdirectory
	lsaDir := filepath.Join(outDir, "windows", "lsa")
	if err := winutil.EnsureDir(lsaDir); err != nil {
		return fmt.Errorf("failed to create lsa directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewLSAManifest(hostname)

	// Collect LSA policy information
	if err := w.collectLSAPolicy(ctx, lsaDir, manifest); err != nil {
		manifest.AddError("lsa_policy", fmt.Sprintf("Failed to collect LSA policy: %v", err))
	}

	// Collect authentication packages
	if err := w.collectAuthPackages(ctx, lsaDir, manifest); err != nil {
		manifest.AddError("auth_packages", fmt.Sprintf("Failed to collect authentication packages: %v", err))
	}

	// Collect domain information
	if err := w.collectDomainInfo(ctx, lsaDir, manifest); err != nil {
		manifest.AddError("domain_info", fmt.Sprintf("Failed to collect domain info: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(lsaDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectLSAPolicy collects LSA policy and security settings.
func (w *WinLSA) collectLSAPolicy(ctx context.Context, outDir string, manifest *LSAManifest) error {
	outputPath := filepath.Join(outDir, "lsa_policy.txt")

	output := "LSA Policy and Security Settings:\n\n"
	output += "Note: LSA Secrets extraction requires specialized tools and high privileges.\n"
	output += "This collection focuses on LSA policy information accessible via standard APIs.\n\n"

	// Get security policy information
	output += "=== Security Policy Settings ===\n"
	secpolCmd := []string{"/C", "secedit /export /cfg temp_secpol.inf && type temp_secpol.inf && del temp_secpol.inf"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", secpolCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting security policy: %v\n", err)
	}
	output += "\n"

	// Get user rights assignments
	output += "=== User Rights Assignments ===\n"
	rightsCmd := []string{"/C", "whoami /priv"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", rightsCmd); err == nil {
		output += "Current process privileges:\n"
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting current privileges: %v\n", err)
	}
	output += "\n"

	// Get audit policy
	output += "=== Audit Policy ===\n"
	auditCmd := []string{"/C", "auditpol /get /category:*"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", auditCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting audit policy: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write LSA policy: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("lsa_policy.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "lsa_policy", "LSA policy and security settings information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectAuthPackages collects authentication packages and SSP information.
func (w *WinLSA) collectAuthPackages(ctx context.Context, outDir string, manifest *LSAManifest) error {
	outputPath := filepath.Join(outDir, "auth_packages.txt")

	output := "Authentication Packages and Security Support Providers:\n\n"

	// Query authentication packages from registry
	output += "=== Authentication Packages (Registry) ===\n"
	authPkgKey := "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
	authPkgCmd := []string{"query", authPkgKey, "/v", "Authentication Packages"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", authPkgCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error querying authentication packages: %v\n", err)
	}
	output += "\n"

	// Query security packages
	output += "=== Security Packages (Registry) ===\n"
	secPkgCmd := []string{"query", authPkgKey, "/v", "Security Packages"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", secPkgCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error querying security packages: %v\n", err)
	}
	output += "\n"

	// Query notification packages
	output += "=== Notification Packages (Registry) ===\n"
	notifyPkgCmd := []string{"query", authPkgKey, "/v", "Notification Packages"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", notifyPkgCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error querying notification packages: %v\n", err)
	}
	output += "\n"

	// Get SSP configuration
	output += "=== Security Support Provider Configuration ===\n"
	sspKey := "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders"
	sspCmd := []string{"query", sspKey, "/s"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", sspCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error querying SSP configuration: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write auth packages: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("auth_packages.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "auth_packages", "Authentication packages and security support providers")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectDomainInfo collects domain and trust information.
func (w *WinLSA) collectDomainInfo(ctx context.Context, outDir string, manifest *LSAManifest) error {
	outputPath := filepath.Join(outDir, "domain_info.txt")

	output := "Domain and Trust Information:\n\n"

	// Get domain information
	output += "=== Domain Information ===\n"
	domainCmd := []string{"/C", "wmic computersystem get domain,domainrole,partofdomain,workgroup"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", domainCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting domain info: %v\n", err)
	}
	output += "\n"

	// Get trust information (if domain-joined)
	output += "=== Trust Information ===\n"
	trustCmd := []string{"/C", "nltest /domain_trusts"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", trustCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting trust info (may not be domain-joined): %v\n", err)
	}
	output += "\n"

	// Get domain controller information
	output += "=== Domain Controller Information ===\n"
	dcCmd := []string{"/C", "nltest /dsgetdc:"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", dcCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting DC info (may not be domain-joined): %v\n", err)
	}
	output += "\n"

	// Get logon server
	output += "=== Logon Server ===\n"
	logonCmd := []string{"/C", "echo %LOGONSERVER%"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", logonCmd); err == nil {
		output += fmt.Sprintf("Logon Server: %s", string(result))
	} else {
		output += fmt.Sprintf("Error getting logon server: %v\n", err)
	}
	output += "\n"

	// Get group policy information
	output += "=== Group Policy Information ===\n"
	gpCmd := []string{"/C", "gpresult /r"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", gpCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting group policy info: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write domain info: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("domain_info.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "domain_info", "Domain membership and trust relationship information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}