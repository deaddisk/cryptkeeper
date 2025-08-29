//go:build windows

package win_firewall_net

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinFirewallNet represents the Windows firewall/network collection module.
type WinFirewallNet struct{}

// NewWinFirewallNet creates a new Windows firewall/network collection module.
func NewWinFirewallNet() *WinFirewallNet {
	return &WinFirewallNet{}
}

// Name returns the module's identifier.
func (w *WinFirewallNet) Name() string {
	return "windows/firewall_net"
}

// Collect copies Windows firewall logs and network configuration.
func (w *WinFirewallNet) Collect(ctx context.Context, outDir string) error {
	// Create the windows/firewall_net subdirectory
	firewallDir := filepath.Join(outDir, "windows", "firewall_net")
	if err := winutil.EnsureDir(firewallDir); err != nil {
		return fmt.Errorf("failed to create firewall_net directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewFirewallNetManifest(hostname)

	// Initialize size constraints
	constraints := winutil.NewSizeConstraints()

	// Get SystemRoot path (usually C:\Windows)
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemDrive := os.Getenv("SystemDrive")
		if systemDrive == "" {
			systemDrive = "C:"
		}
		systemRoot = filepath.Join(systemDrive, "Windows")
	}

	// Collect Windows Firewall logs
	firewallLogDir := filepath.Join(systemRoot, "System32", "LogFiles", "Firewall")
	if err := w.collectFirewallLogs(ctx, firewallLogDir, firewallDir, manifest, constraints); err != nil {
		manifest.AddError("firewall_logs", fmt.Sprintf("Failed to collect firewall logs: %v", err))
	}

	// Collect network configuration information
	if err := w.collectNetworkInfo(ctx, firewallDir, manifest); err != nil {
		manifest.AddError("network_info", fmt.Sprintf("Failed to collect network info: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(firewallDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectFirewallLogs collects Windows Firewall log files.
func (w *WinFirewallNet) collectFirewallLogs(ctx context.Context, sourceDir, outDir string, manifest *FirewallNetManifest, constraints *winutil.SizeConstraints) error {
	// Create firewall_logs subdirectory
	logsOutDir := filepath.Join(outDir, "firewall_logs")
	if err := winutil.EnsureDir(logsOutDir); err != nil {
		return fmt.Errorf("failed to create firewall_logs output directory: %w", err)
	}

	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return fmt.Errorf("failed to read firewall logs directory: %w", err)
	}

	for _, entry := range entries {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if entry.IsDir() {
			continue
		}

		filename := entry.Name()
		
		// Only collect firewall log files
		if !w.isFirewallLogFile(filename) {
			continue
		}

		manifest.IncrementTotalFiles()

		srcPath := filepath.Join(sourceDir, filename)
		destPath := filepath.Join(logsOutDir, filename)

		// Get file info
		stat, err := os.Stat(srcPath)
		if err != nil {
			manifest.AddError(srcPath, fmt.Sprintf("Failed to stat file: %v", err))
			continue
		}

		// Use tail copy for large log files with size constraints
		size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints)
		if err != nil {
			manifest.AddError(srcPath, fmt.Sprintf("Failed to copy file: %v", err))
			continue
		}

		// Generate relative path for manifest
		relPath := filepath.Join("firewall_logs", filename)
		note := fmt.Sprintf("Windows Firewall log file (%s)", filename)

		// Add to manifest
		manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "firewall_log", note)
	}

	return nil
}

// collectNetworkInfo collects network configuration using system commands.
func (w *WinFirewallNet) collectNetworkInfo(ctx context.Context, outDir string, manifest *FirewallNetManifest) error {
	// Collect ipconfig /all output
	if err := w.collectIPConfig(ctx, outDir, manifest); err != nil {
		manifest.AddError("ipconfig", fmt.Sprintf("Failed to collect ipconfig output: %v", err))
	}

	// Collect route print output  
	if err := w.collectRouteTable(ctx, outDir, manifest); err != nil {
		manifest.AddError("route_table", fmt.Sprintf("Failed to collect route table: %v", err))
	}

	return nil
}

// collectIPConfig runs ipconfig /all and saves output.
func (w *WinFirewallNet) collectIPConfig(ctx context.Context, outDir string, manifest *FirewallNetManifest) error {
	outputPath := filepath.Join(outDir, "ipconfig_all.txt")
	
	// Run ipconfig /all
	args := []string{"/all"}
	output, err := winutil.RunCommandWithOutput(ctx, "ipconfig", args)
	if err != nil {
		return fmt.Errorf("failed to run ipconfig /all: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write ipconfig output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat ipconfig output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash ipconfig output: %w", err)
	}

	manifest.AddItem("ipconfig_all.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "network_info", "Output of ipconfig /all command")
	manifest.IncrementTotalFiles()

	return nil
}

// collectRouteTable runs route print and saves output.
func (w *WinFirewallNet) collectRouteTable(ctx context.Context, outDir string, manifest *FirewallNetManifest) error {
	outputPath := filepath.Join(outDir, "route_print.txt")
	
	// Run route print
	args := []string{"print"}
	output, err := winutil.RunCommandWithOutput(ctx, "route", args)
	if err != nil {
		return fmt.Errorf("failed to run route print: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write route output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat route output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash route output: %w", err)
	}

	manifest.AddItem("route_print.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "network_info", "Output of route print command")
	manifest.IncrementTotalFiles()

	return nil
}

// isFirewallLogFile determines if a file is a Windows Firewall log file.
func (w *WinFirewallNet) isFirewallLogFile(filename string) bool {
	lowerFilename := strings.ToLower(filename)
	
	// Windows Firewall log files are typically named pfirewall.log
	return lowerFilename == "pfirewall.log" || 
		   strings.HasPrefix(lowerFilename, "pfirewall") ||
		   (strings.Contains(lowerFilename, "firewall") && strings.HasSuffix(lowerFilename, ".log"))
}