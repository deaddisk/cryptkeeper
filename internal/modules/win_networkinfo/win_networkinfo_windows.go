//go:build windows

package win_networkinfo

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"cryptkeeper/internal/winutil"
)

// WinNetworkInfo represents the Windows network information collection module.
type WinNetworkInfo struct{}

// NewWinNetworkInfo creates a new Windows network information collection module.
func NewWinNetworkInfo() *WinNetworkInfo {
	return &WinNetworkInfo{}
}

// Name returns the module's identifier.
func (w *WinNetworkInfo) Name() string {
	return "windows/networkinfo"
}

// Collect gathers Windows network information including DNS cache, connections, ARP table, and SMB shares.
func (w *WinNetworkInfo) Collect(ctx context.Context, outDir string) error {
	// Create the windows/networkinfo subdirectory
	networkDir := filepath.Join(outDir, "windows", "networkinfo")
	if err := winutil.EnsureDir(networkDir); err != nil {
		return fmt.Errorf("failed to create networkinfo directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewNetworkInfoManifest(hostname)

	// Collect DNS cache
	if err := w.collectDNSCache(ctx, networkDir, manifest); err != nil {
		manifest.AddError("dns_cache", fmt.Sprintf("Failed to collect DNS cache: %v", err))
	}

	// Collect network connections
	if err := w.collectNetworkConnections(ctx, networkDir, manifest); err != nil {
		manifest.AddError("network_connections", fmt.Sprintf("Failed to collect network connections: %v", err))
	}

	// Collect ARP table
	if err := w.collectARPTable(ctx, networkDir, manifest); err != nil {
		manifest.AddError("arp_table", fmt.Sprintf("Failed to collect ARP table: %v", err))
	}

	// Collect SMB shares
	if err := w.collectSMBShares(ctx, networkDir, manifest); err != nil {
		manifest.AddError("smb_shares", fmt.Sprintf("Failed to collect SMB shares: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(networkDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectDNSCache collects the DNS resolver cache using ipconfig /displaydns.
func (w *WinNetworkInfo) collectDNSCache(ctx context.Context, outDir string, manifest *NetworkInfoManifest) error {
	outputPath := filepath.Join(outDir, "dns_cache.txt")

	// Run ipconfig /displaydns
	args := []string{"/displaydns"}
	output, err := winutil.RunCommandWithOutput(ctx, "ipconfig", args)
	if err != nil {
		return fmt.Errorf("failed to run ipconfig /displaydns: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write DNS cache output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat DNS cache output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash DNS cache output: %w", err)
	}

	manifest.AddItem("dns_cache.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "dns_cache", "DNS resolver cache from ipconfig /displaydns")
	manifest.IncrementTotalFiles()

	return nil
}

// collectNetworkConnections collects active network connections using netstat.
func (w *WinNetworkInfo) collectNetworkConnections(ctx context.Context, outDir string, manifest *NetworkInfoManifest) error {
	outputPath := filepath.Join(outDir, "network_connections.txt")

	// Run netstat -ano (all connections, numerical, with process IDs)
	args := []string{"-ano"}
	output, err := winutil.RunCommandWithOutput(ctx, "netstat", args)
	if err != nil {
		return fmt.Errorf("failed to run netstat -ano: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write netstat output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat netstat output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash netstat output: %w", err)
	}

	manifest.AddItem("network_connections.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "network_connections", "Active network connections from netstat -ano")
	manifest.IncrementTotalFiles()

	return nil
}

// collectARPTable collects the ARP table using arp -a.
func (w *WinNetworkInfo) collectARPTable(ctx context.Context, outDir string, manifest *NetworkInfoManifest) error {
	outputPath := filepath.Join(outDir, "arp_table.txt")

	// Run arp -a
	args := []string{"-a"}
	output, err := winutil.RunCommandWithOutput(ctx, "arp", args)
	if err != nil {
		return fmt.Errorf("failed to run arp -a: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write ARP table output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat ARP table output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash ARP table output: %w", err)
	}

	manifest.AddItem("arp_table.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "arp_table", "ARP table from arp -a command")
	manifest.IncrementTotalFiles()

	return nil
}

// collectSMBShares collects SMB share information using net share.
func (w *WinNetworkInfo) collectSMBShares(ctx context.Context, outDir string, manifest *NetworkInfoManifest) error {
	outputPath := filepath.Join(outDir, "smb_shares.txt")

	// Run net share
	args := []string{"share"}
	output, err := winutil.RunCommandWithOutput(ctx, "net", args)
	if err != nil {
		return fmt.Errorf("failed to run net share: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write SMB shares output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat SMB shares output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash SMB shares output: %w", err)
	}

	manifest.AddItem("smb_shares.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "smb_shares", "SMB shares from net share command")
	manifest.IncrementTotalFiles()

	return nil
}