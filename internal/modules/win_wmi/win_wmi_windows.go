//go:build windows

package win_wmi

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinWMI represents the Windows WMI collection module.
type WinWMI struct{}

// NewWinWMI creates a new Windows WMI collection module.
func NewWinWMI() *WinWMI {
	return &WinWMI{}
}

// Name returns the module's identifier.
func (w *WinWMI) Name() string {
	return "windows/wmi"
}

// Collect copies Windows WMI repository files and creates subscription reports.
func (w *WinWMI) Collect(ctx context.Context, outDir string) error {
	// Create the windows/wmi subdirectory
	wmiDir := filepath.Join(outDir, "windows", "wmi")
	if err := winutil.EnsureDir(wmiDir); err != nil {
		return fmt.Errorf("failed to create wmi directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewWMIManifest(hostname)

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

	// Collect WMI repository files from System32\wbem\Repository\
	wmiRepoDir := filepath.Join(systemRoot, "System32", "wbem", "Repository")
	if err := w.collectWMIRepository(ctx, wmiRepoDir, wmiDir, manifest, constraints); err != nil {
		manifest.AddError("wmi_repository", fmt.Sprintf("Failed to collect WMI repository: %v", err))
	}

	// Collect WMI event subscriptions (PowerShell method)
	if err := w.collectWMISubscriptions(ctx, wmiDir, manifest); err != nil {
		manifest.AddError("wmi_subscriptions", fmt.Sprintf("Failed to collect WMI subscriptions: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(wmiDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectWMIRepository collects WMI repository files.
func (w *WinWMI) collectWMIRepository(ctx context.Context, sourceDir, outDir string, manifest *WMIManifest, constraints *winutil.SizeConstraints) error {
	// Create repository subdirectory
	repoOutDir := filepath.Join(outDir, "repository")
	if err := winutil.EnsureDir(repoOutDir); err != nil {
		return fmt.Errorf("failed to create repository output directory: %w", err)
	}

	return filepath.WalkDir(sourceDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to access path: %v", err))
			return nil // Continue walking
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if d.IsDir() {
			return nil
		}

		// Get relative path from source directory
		relPath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to get relative path: %v", err))
			return nil
		}

		manifest.IncrementTotalFiles()

		// Create destination path
		destPath := filepath.Join(repoOutDir, relPath)
		
		// Ensure destination directory exists
		destDir := filepath.Dir(destPath)
		if err := winutil.EnsureDir(destDir); err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to create destination directory: %v", err))
			return nil
		}

		// Get file info
		stat, err := os.Stat(path)
		if err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to stat file: %v", err))
			return nil
		}

		// Use smart copy with size constraints
		size, sha256Hex, truncated, err := winutil.SmartCopy(path, destPath, constraints)
		if err != nil {
			manifest.AddError(path, fmt.Sprintf("Failed to copy file: %v", err))
			return nil
		}

		// Determine file type and generate note
		fileType, note := w.classifyWMIFile(filepath.Base(path))

		// Generate manifest path relative to wmi directory
		manifestRelPath := filepath.Join("repository", relPath)

		// Add to manifest
		manifest.AddItem(manifestRelPath, size, sha256Hex, truncated, stat.ModTime(), fileType, note)

		return nil
	})
}

// collectWMISubscriptions collects WMI event subscriptions using PowerShell.
func (w *WinWMI) collectWMISubscriptions(ctx context.Context, outDir string, manifest *WMIManifest) error {
	outputPath := filepath.Join(outDir, "wmi_subscriptions.json")
	
	// PowerShell script to export WMI permanent event subscriptions
	psScript := `
$subscriptions = @()
try {
    $filters = Get-WmiObject -Namespace root\subscription -Class __EventFilter
    $consumers = Get-WmiObject -Namespace root\subscription -Class __EventConsumer
    $bindings = Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding
    
    $subscriptions += @{
        "filters" = $filters | Select-Object Name, Query, QueryLanguage
        "consumers" = $consumers | Select-Object Name, CommandLineTemplate, ExecutablePath, ScriptFileName, ScriptText
        "bindings" = $bindings | Select-Object Filter, Consumer
    }
} catch {
    $subscriptions += @{
        "error" = "Failed to enumerate WMI subscriptions: $($_.Exception.Message)"
    }
}
$subscriptions | ConvertTo-Json -Depth 10
`

	// Run PowerShell script
	args := []string{"-Command", psScript}
	output, err := winutil.RunCommandWithOutput(ctx, "powershell", args)
	if err != nil {
		// Try alternative approach with error included
		errorOutput := fmt.Sprintf(`{"error": "Failed to run PowerShell: %s"}`, err.Error())
		output = []byte(errorOutput)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write WMI subscriptions output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat WMI subscriptions output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash WMI subscriptions output: %w", err)
	}

	manifest.AddItem("wmi_subscriptions.json", stat.Size(), sha256Hex, false, stat.ModTime(), "subscription_info", "WMI permanent event subscriptions export")
	manifest.IncrementTotalFiles()

	return nil
}

// classifyWMIFile determines the file type and generates a description for WMI files.
func (w *WinWMI) classifyWMIFile(filename string) (fileType, note string) {
	lowerFilename := strings.ToLower(filename)
	
	switch lowerFilename {
	case "objects.data":
		return "repository", "WMI repository primary objects database"
	case "index.btr":
		return "repository", "WMI repository index file"
	case "mapping1.map", "mapping2.map", "mapping3.map":
		return "repository", fmt.Sprintf("WMI repository mapping file (%s)", filename)
	default:
		if strings.HasSuffix(lowerFilename, ".btr") {
			return "repository", fmt.Sprintf("WMI repository B-tree file (%s)", filename)
		}
		if strings.HasSuffix(lowerFilename, ".map") {
			return "repository", fmt.Sprintf("WMI repository mapping file (%s)", filename)
		}
		return "repository", fmt.Sprintf("WMI repository file (%s)", filename)
	}
}