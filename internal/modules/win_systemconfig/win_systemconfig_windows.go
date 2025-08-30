//go:build windows

package win_systemconfig

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"cryptkeeper/internal/winutil"
)

// WinSystemConfig represents the Windows system configuration collection module.
type WinSystemConfig struct{}

// NewWinSystemConfig creates a new Windows system configuration collection module.
func NewWinSystemConfig() *WinSystemConfig {
	return &WinSystemConfig{}
}

// Name returns the module's identifier.
func (w *WinSystemConfig) Name() string {
	return "windows/systemconfig"
}

// Collect gathers Windows system configuration including services, startup locations, environment, timezone, and hosts file.
func (w *WinSystemConfig) Collect(ctx context.Context, outDir string) error {
	// Create the windows/systemconfig subdirectory
	configDir := filepath.Join(outDir, "windows", "systemconfig")
	if err := winutil.EnsureDir(configDir); err != nil {
		return fmt.Errorf("failed to create systemconfig directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewSystemConfigManifest(hostname)

	// Collect services configuration
	if err := w.collectServicesConfig(ctx, configDir, manifest); err != nil {
		manifest.AddError("services_config", fmt.Sprintf("Failed to collect services config: %v", err))
	}

	// Collect startup locations
	if err := w.collectStartupLocations(ctx, configDir, manifest); err != nil {
		manifest.AddError("startup_locations", fmt.Sprintf("Failed to collect startup locations: %v", err))
	}

	// Collect environment variables
	if err := w.collectEnvironmentVariables(ctx, configDir, manifest); err != nil {
		manifest.AddError("environment_variables", fmt.Sprintf("Failed to collect environment variables: %v", err))
	}

	// Collect timezone configuration
	if err := w.collectTimezoneConfig(ctx, configDir, manifest); err != nil {
		manifest.AddError("timezone_config", fmt.Sprintf("Failed to collect timezone config: %v", err))
	}

	// Collect hosts file
	if err := w.collectHostsFile(ctx, configDir, manifest); err != nil {
		manifest.AddError("hosts_file", fmt.Sprintf("Failed to collect hosts file: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(configDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectServicesConfig collects detailed service configuration using sc query.
func (w *WinSystemConfig) collectServicesConfig(ctx context.Context, outDir string, manifest *SystemConfigManifest) error {
	outputPath := filepath.Join(outDir, "services_config.txt")

	// Run sc query to get all services
	args := []string{"query", "state=", "all"}
	output, err := winutil.RunCommandWithOutput(ctx, "sc", args)
	if err != nil {
		return fmt.Errorf("failed to run sc query: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write services config output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat services config output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash services config output: %w", err)
	}

	manifest.AddItem("services_config.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "services", "Windows services configuration from sc query")
	manifest.IncrementTotalFiles()

	return nil
}

// collectStartupLocations collects startup program information.
func (w *WinSystemConfig) collectStartupLocations(ctx context.Context, outDir string, manifest *SystemConfigManifest) error {
	// Use wmic to get startup programs
	outputPath := filepath.Join(outDir, "startup_programs.csv")
	
	args := []string{"startup", "get", "Name,Command,Location,User", "/format:csv"}
	output, err := winutil.RunCommandWithOutput(ctx, "wmic", args)
	if err != nil {
		return fmt.Errorf("failed to run wmic startup: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write startup programs output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat startup programs output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash startup programs output: %w", err)
	}

	manifest.AddItem("startup_programs.csv", stat.Size(), sha256Hex, false, stat.ModTime(), "startup", "Startup programs from wmic startup command")
	manifest.IncrementTotalFiles()

	return nil
}

// collectEnvironmentVariables collects system and user environment variables.
func (w *WinSystemConfig) collectEnvironmentVariables(ctx context.Context, outDir string, manifest *SystemConfigManifest) error {
	outputPath := filepath.Join(outDir, "environment_variables.txt")

	// Run set command to get all environment variables
	args := []string{}
	output, err := winutil.RunCommandWithOutput(ctx, "set", args)
	if err != nil {
		return fmt.Errorf("failed to run set command: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write environment variables output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat environment variables output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash environment variables output: %w", err)
	}

	manifest.AddItem("environment_variables.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "environment", "Environment variables from set command")
	manifest.IncrementTotalFiles()

	return nil
}

// collectTimezoneConfig collects timezone and time synchronization settings.
func (w *WinSystemConfig) collectTimezoneConfig(ctx context.Context, outDir string, manifest *SystemConfigManifest) error {
	outputPath := filepath.Join(outDir, "timezone_config.txt")

	// Run w32tm /query /status to get time service status
	args := []string{"/query", "/status"}
	output, err := winutil.RunCommandWithOutput(ctx, "w32tm", args)
	if err != nil {
		// Try alternative approach with tzutil
		args = []string{"/g"}
		output, err = winutil.RunCommandWithOutput(ctx, "tzutil", args)
		if err != nil {
			return fmt.Errorf("failed to get timezone config: %w", err)
		}
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write timezone config output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat timezone config output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash timezone config output: %w", err)
	}

	manifest.AddItem("timezone_config.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "timezone", "Timezone and time synchronization configuration")
	manifest.IncrementTotalFiles()

	return nil
}

// collectHostsFile collects the Windows hosts file.
func (w *WinSystemConfig) collectHostsFile(ctx context.Context, outDir string, manifest *SystemConfigManifest) error {
	// Get SystemRoot path (usually C:\Windows)
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemDrive := os.Getenv("SystemDrive")
		if systemDrive == "" {
			systemDrive = "C:"
		}
		systemRoot = filepath.Join(systemDrive, "Windows")
	}

	hostsPath := filepath.Join(systemRoot, "System32", "drivers", "etc", "hosts")
	
	// Check if hosts file exists
	stat, err := os.Stat(hostsPath)
	if err != nil {
		return fmt.Errorf("hosts file not found: %w", err)
	}

	manifest.IncrementTotalFiles()

	destPath := filepath.Join(outDir, "hosts")

	// Copy the hosts file
	srcFile, err := winutil.OpenForCopy(hostsPath)
	if err != nil {
		return fmt.Errorf("failed to open hosts file: %w", err)
	}
	defer srcFile.Close()

	size, sha256Hex, err := winutil.CopyFileStreaming(srcFile, destPath)
	if err != nil {
		return fmt.Errorf("failed to copy hosts file: %w", err)
	}

	manifest.AddItem("hosts", size, sha256Hex, false, stat.ModTime(), "hosts", "Windows hosts file from System32/drivers/etc/hosts")

	return nil
}