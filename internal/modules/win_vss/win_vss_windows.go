//go:build windows

package win_vss

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinVSS represents the Volume Shadow Copy Service collection module.
type WinVSS struct{}

// NewWinVSS creates a new Volume Shadow Copy Service collection module.
func NewWinVSS() *WinVSS {
	return &WinVSS{}
}

// Name returns the module's identifier.
func (w *WinVSS) Name() string {
	return "windows/vss"
}

// Collect gathers Volume Shadow Copy Service information and metadata.
func (w *WinVSS) Collect(ctx context.Context, outDir string) error {
	// Create the windows/vss subdirectory
	vssDir := filepath.Join(outDir, "windows", "vss")
	if err := winutil.EnsureDir(vssDir); err != nil {
		return fmt.Errorf("failed to create vss directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewVSSManifest(hostname)

	// Collect VSS information using vssadmin
	if err := w.collectVSSAdminInfo(ctx, vssDir, manifest); err != nil {
		manifest.AddError("vssadmin_info", fmt.Sprintf("Failed to collect vssadmin info: %v", err))
	}

	// Collect shadow copy information using wmic
	if err := w.collectShadowCopies(ctx, vssDir, manifest); err != nil {
		manifest.AddError("shadow_copies", fmt.Sprintf("Failed to collect shadow copies: %v", err))
	}

	// Collect VSS writer information
	if err := w.collectVSSWriters(ctx, vssDir, manifest); err != nil {
		manifest.AddError("vss_writers", fmt.Sprintf("Failed to collect VSS writers: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(vssDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectVSSAdminInfo collects information using vssadmin command.
func (w *WinVSS) collectVSSAdminInfo(ctx context.Context, outDir string, manifest *VSSManifest) error {
	outputPath := filepath.Join(outDir, "vssadmin_info.txt")

	output := "Volume Shadow Copy Service Information:\n\n"

	// List shadow copies
	output += "=== Shadow Copies ===\n"
	shadowCmd := []string{"list", "shadows"}
	if result, err := winutil.RunCommandWithOutput(ctx, "vssadmin", shadowCmd); err == nil {
		output += string(result)
		// Count shadow copies
		shadowCount := strings.Count(string(result), "Shadow Copy ID:")
		manifest.SetShadowCopiesFound(shadowCount)
	} else {
		output += fmt.Sprintf("Error listing shadow copies: %v\n", err)
		output += "This may indicate insufficient privileges or VSS is not available.\n"
	}
	output += "\n"

	// List providers
	output += "=== VSS Providers ===\n"
	providerCmd := []string{"list", "providers"}
	if result, err := winutil.RunCommandWithOutput(ctx, "vssadmin", providerCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error listing VSS providers: %v\n", err)
	}
	output += "\n"

	// List writers
	output += "=== VSS Writers ===\n"
	writerCmd := []string{"list", "writers"}
	if result, err := winutil.RunCommandWithOutput(ctx, "vssadmin", writerCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error listing VSS writers: %v\n", err)
	}
	output += "\n"

	// List volumes
	output += "=== Shadow Storage Associations ===\n"
	storageCmd := []string{"list", "shadowstorage"}
	if result, err := winutil.RunCommandWithOutput(ctx, "vssadmin", storageCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error listing shadow storage: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write vssadmin info: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("vssadmin_info.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "vss_info", "Volume Shadow Copy Service information from vssadmin")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectShadowCopies collects shadow copy information using WMIC.
func (w *WinVSS) collectShadowCopies(ctx context.Context, outDir string, manifest *VSSManifest) error {
	outputPath := filepath.Join(outDir, "shadow_copies_wmic.txt")

	output := "Shadow Copies Information (via WMIC):\n\n"

	// Get shadow copy information
	wmicCmd := []string{"/C", "wmic shadowcopy get /format:list"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", wmicCmd); err == nil {
		output += "=== Shadow Copy Details ===\n"
		output += string(result)
		output += "\n"
	} else {
		output += fmt.Sprintf("Error getting shadow copy details: %v\n", err)
	}

	// Get shadow storage information
	storageCmd := []string{"/C", "wmic shadowstorage get /format:list"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", storageCmd); err == nil {
		output += "=== Shadow Storage Details ===\n"
		output += string(result)
		output += "\n"
	} else {
		output += fmt.Sprintf("Error getting shadow storage details: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write shadow copies info: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("shadow_copies_wmic.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "shadow_copies", "Shadow copy information from WMIC")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectVSSWriters collects detailed VSS writer information.
func (w *WinVSS) collectVSSWriters(ctx context.Context, outDir string, manifest *VSSManifest) error {
	outputPath := filepath.Join(outDir, "vss_writers_detail.txt")

	output := "VSS Writers Detailed Information:\n\n"
	output += "Note: VSS Writers are applications that participate in shadow copy creation.\n\n"

	// Use PowerShell to get more detailed writer information
	psScript := `Get-WmiObject -Class Win32_ShadowProvider | Format-List *`
	psCmd := []string{"-Command", psScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
		output += "=== Shadow Providers (PowerShell) ===\n"
		output += string(result)
		output += "\n"
	} else {
		output += fmt.Sprintf("Error getting shadow providers via PowerShell: %v\n", err)
	}

	// Get additional writer information using vssadmin with detailed output
	writerDetailCmd := []string{"list", "writers", "detailed"}
	if result, err := winutil.RunCommandWithOutput(ctx, "vssadmin", writerDetailCmd); err == nil {
		output += "=== VSS Writers (Detailed) ===\n"
		output += string(result)
		output += "\n"
	} else {
		// Try without detailed flag if it's not supported
		writerCmd := []string{"list", "writers"}
		if result, err := winutil.RunCommandWithOutput(ctx, "vssadmin", writerCmd); err == nil {
			output += "=== VSS Writers ===\n"
			output += string(result)
			output += "\n"
		} else {
			output += fmt.Sprintf("Error getting VSS writers: %v\n", err)
		}
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write VSS writers info: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("vss_writers_detail.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "vss_config", "Detailed VSS writers and providers information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}