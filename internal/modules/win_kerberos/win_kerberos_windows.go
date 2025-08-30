//go:build windows

package win_kerberos

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinKerberos represents the Kerberos authentication collection module.
type WinKerberos struct{}

// NewWinKerberos creates a new Kerberos authentication collection module.
func NewWinKerberos() *WinKerberos {
	return &WinKerberos{}
}

// Name returns the module's identifier.
func (w *WinKerberos) Name() string {
	return "windows/kerberos"
}

// Collect gathers Kerberos authentication information and ticket cache data.
func (w *WinKerberos) Collect(ctx context.Context, outDir string) error {
	// Create the windows/kerberos subdirectory
	kerberosDir := filepath.Join(outDir, "windows", "kerberos")
	if err := winutil.EnsureDir(kerberosDir); err != nil {
		return fmt.Errorf("failed to create kerberos directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewKerberosManifest(hostname)

	// Collect Kerberos tickets
	if err := w.collectKerberosTickets(ctx, kerberosDir, manifest); err != nil {
		manifest.AddError("kerberos_tickets", fmt.Sprintf("Failed to collect Kerberos tickets: %v", err))
	}

	// Collect Kerberos configuration
	if err := w.collectKerberosConfig(ctx, kerberosDir, manifest); err != nil {
		manifest.AddError("kerberos_config", fmt.Sprintf("Failed to collect Kerberos config: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(kerberosDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectKerberosTickets collects current Kerberos tickets and cache information.
func (w *WinKerberos) collectKerberosTickets(ctx context.Context, outDir string, manifest *KerberosManifest) error {
	outputPath := filepath.Join(outDir, "kerberos_tickets.txt")

	output := "Kerberos Tickets and Cache Information:\n\n"

	// Use klist to show current tickets
	output += "=== Current Kerberos Tickets (klist) ===\n"
	klistCmd := []string{"/C", "klist"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", klistCmd); err == nil {
		output += string(result)
		// Count tickets
		ticketCount := strings.Count(string(result), "Client:")
		manifest.SetTicketsFound(ticketCount)
	} else {
		output += fmt.Sprintf("Error running klist: %v\n", err)
		output += "Note: No Kerberos tickets may be cached, or klist command is not available.\n"
	}
	output += "\n"

	// Get ticket granting tickets
	output += "=== Ticket Granting Tickets (klist tgt) ===\n"
	tgtCmd := []string{"/C", "klist tgt"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", tgtCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting TGT: %v\n", err)
	}
	output += "\n"

	// Get ticket cache information
	output += "=== Ticket Cache Information ===\n"
	cacheCmd := []string{"/C", "klist -li 0x3e7"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", cacheCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting ticket cache info: %v\n", err)
	}
	output += "\n"

	// Try PowerShell approach for additional ticket information
	output += "=== Additional Ticket Information (PowerShell) ===\n"
	psScript := `Add-Type -AssemblyName System.IdentityModel; [System.IdentityModel.Tokens.KerberosRequestorSecurityToken]::GetRequest("HOST/localhost")`
	psCmd := []string{"-Command", psScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting additional ticket info via PowerShell: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write kerberos tickets: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("kerberos_tickets.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "kerberos_tickets", "Current Kerberos tickets and cache information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectKerberosConfig collects Kerberos configuration and realm information.
func (w *WinKerberos) collectKerberosConfig(ctx context.Context, outDir string, manifest *KerberosManifest) error {
	outputPath := filepath.Join(outDir, "kerberos_config.txt")

	output := "Kerberos Configuration and Realm Information:\n\n"

	// Get Kerberos configuration from registry
	output += "=== Kerberos Configuration (Registry) ===\n"
	kerbKey := "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\Kerberos"
	kerbCmd := []string{"query", kerbKey, "/s"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", kerbCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error querying Kerberos registry: %v\n", err)
	}
	output += "\n"

	// Get domain controller information (related to Kerberos KDC)
	output += "=== Domain Controller / KDC Information ===\n"
	dcCmd := []string{"/C", "nltest /dsgetdc:"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", dcCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting DC info: %v\n", err)
	}
	output += "\n"

	// Get time information (important for Kerberos)
	output += "=== System Time Information (Kerberos Time Sync) ===\n"
	timeCmd := []string{"/C", "w32tm /query /status"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", timeCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting time sync info: %v\n", err)
	}
	output += "\n"

	// Get DNS configuration (important for Kerberos realm resolution)
	output += "=== DNS Configuration (Kerberos Realm Resolution) ===\n"
	dnsCmd := []string{"/C", "nslookup -type=SRV _kerberos._tcp"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", dnsCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting Kerberos SRV records: %v\n", err)
	}
	output += "\n"

	// Get current user's authentication information
	output += "=== Current User Authentication Info ===\n"
	authCmd := []string{"/C", "whoami /user /groups /priv"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", authCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting current user auth info: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write kerberos config: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("kerberos_config.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "krb_config", "Kerberos configuration and realm information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}