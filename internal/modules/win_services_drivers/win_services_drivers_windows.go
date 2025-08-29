//go:build windows

package win_services_drivers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinServicesDrivers represents the Windows services/drivers collection module.
type WinServicesDrivers struct{}

// NewWinServicesDrivers creates a new Windows services/drivers collection module.
func NewWinServicesDrivers() *WinServicesDrivers {
	return &WinServicesDrivers{}
}

// Name returns the module's identifier.
func (w *WinServicesDrivers) Name() string {
	return "windows/services_drivers"
}

// Collect copies Windows driver files and creates system info reports.
func (w *WinServicesDrivers) Collect(ctx context.Context, outDir string) error {
	// Create the windows/services_drivers subdirectory
	servicesDir := filepath.Join(outDir, "windows", "services_drivers")
	if err := winutil.EnsureDir(servicesDir); err != nil {
		return fmt.Errorf("failed to create services_drivers directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewServiceDriverManifest(hostname)

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

	// Collect driver files from System32\drivers\
	driversDir := filepath.Join(systemRoot, "System32", "drivers")
	if err := w.collectDriverFiles(ctx, driversDir, servicesDir, manifest, constraints); err != nil {
		manifest.AddError("drivers_directory", fmt.Sprintf("Failed to collect driver files: %v", err))
	}

	// Collect driverquery output (if available)
	if err := w.collectDriverQuery(ctx, servicesDir, manifest); err != nil {
		manifest.AddError("driverquery", fmt.Sprintf("Failed to collect driverquery output: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(servicesDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectDriverFiles collects driver (.sys) files from the drivers directory.
func (w *WinServicesDrivers) collectDriverFiles(ctx context.Context, sourceDir, outDir string, manifest *ServiceDriverManifest, constraints *winutil.SizeConstraints) error {
	// Create drivers subdirectory
	driversOutDir := filepath.Join(outDir, "drivers")
	if err := winutil.EnsureDir(driversOutDir); err != nil {
		return fmt.Errorf("failed to create drivers output directory: %w", err)
	}

	entries, err := os.ReadDir(sourceDir)
	if err != nil {
		return fmt.Errorf("failed to read drivers directory: %w", err)
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
		
		// Only collect .sys files (Windows drivers)
		if !w.isDriverFile(filename) {
			continue
		}

		manifest.IncrementTotalFiles()

		srcPath := filepath.Join(sourceDir, filename)
		destPath := filepath.Join(driversOutDir, filename)

		// Get file info
		stat, err := os.Stat(srcPath)
		if err != nil {
			manifest.AddError(srcPath, fmt.Sprintf("Failed to stat file: %v", err))
			continue
		}

		// Use smart copy with size constraints
		size, sha256Hex, truncated, err := winutil.SmartCopy(srcPath, destPath, constraints)
		if err != nil {
			manifest.AddError(srcPath, fmt.Sprintf("Failed to copy file: %v", err))
			continue
		}

		// Generate relative path for manifest
		relPath := filepath.Join("drivers", filename)
		note := fmt.Sprintf("Windows system driver (%s)", filename)

		// Add to manifest
		manifest.AddItem(relPath, size, sha256Hex, truncated, stat.ModTime(), "driver", note)
	}

	return nil
}

// collectDriverQuery runs driverquery command and saves output.
func (w *WinServicesDrivers) collectDriverQuery(ctx context.Context, outDir string, manifest *ServiceDriverManifest) error {
	outputPath := filepath.Join(outDir, "driverquery.csv")
	
	// Run driverquery /v /fo csv
	args := []string{"/v", "/fo", "csv"}
	output, err := winutil.RunCommandWithOutput(ctx, "driverquery", args)
	if err != nil {
		return fmt.Errorf("failed to run driverquery: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write driverquery output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat driverquery output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash driverquery output: %w", err)
	}

	manifest.AddItem("driverquery.csv", stat.Size(), sha256Hex, false, stat.ModTime(), "system_info", "Output of driverquery /v /fo csv command")
	manifest.IncrementTotalFiles()

	return nil
}

// isDriverFile determines if a file is a Windows driver file.
func (w *WinServicesDrivers) isDriverFile(filename string) bool {
	return strings.HasSuffix(strings.ToLower(filename), ".sys")
}