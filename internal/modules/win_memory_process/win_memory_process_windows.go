//go:build windows

package win_memory_process

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cryptkeeper/internal/winutil"
)

// WinMemoryProcess represents the Windows memory/process collection module.
type WinMemoryProcess struct{}

// NewWinMemoryProcess creates a new Windows memory/process collection module.
func NewWinMemoryProcess() *WinMemoryProcess {
	return &WinMemoryProcess{}
}

// Name returns the module's identifier.
func (w *WinMemoryProcess) Name() string {
	return "windows/memory_process"
}

// Collect gathers Windows memory and process artifacts including virtual memory files and process information.
func (w *WinMemoryProcess) Collect(ctx context.Context, outDir string) error {
	// Create the windows/memory_process subdirectory
	memoryDir := filepath.Join(outDir, "windows", "memory_process")
	if err := winutil.EnsureDir(memoryDir); err != nil {
		return fmt.Errorf("failed to create memory_process directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewMemoryProcessManifest(hostname)
	constraints := winutil.NewSizeConstraints()

	// Collect process information (instead of full memory dumps due to size)
	if err := w.collectProcessInformation(ctx, memoryDir, manifest); err != nil {
		manifest.AddError("process_information", fmt.Sprintf("Failed to collect process information: %v", err))
	}

	// Collect handle information
	if err := w.collectHandleInformation(ctx, memoryDir, manifest); err != nil {
		manifest.AddError("handle_information", fmt.Sprintf("Failed to collect handle information: %v", err))
	}

	// Collect memory usage information
	if err := w.collectMemoryInformation(ctx, memoryDir, manifest); err != nil {
		manifest.AddError("memory_information", fmt.Sprintf("Failed to collect memory information: %v", err))
	}

	// Collect virtual memory files (pagefile, swapfile, hiberfil) - metadata only due to size
	if err := w.collectVirtualMemoryInfo(ctx, memoryDir, manifest, constraints); err != nil {
		manifest.AddError("virtual_memory_files", fmt.Sprintf("Failed to collect virtual memory files: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(memoryDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectProcessInformation collects detailed process information using tasklist and wmic.
func (w *WinMemoryProcess) collectProcessInformation(ctx context.Context, outDir string, manifest *MemoryProcessManifest) error {
	// Collect detailed process list with modules
	outputPath := filepath.Join(outDir, "process_list_detailed.csv")
	
	args := []string{"process", "get", "Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath,CreationDate,UserModeTime,KernelModeTime,WorkingSetSize,VirtualSize", "/format:csv"}
	output, err := winutil.RunCommandWithOutput(ctx, "wmic", args)
	if err != nil {
		return fmt.Errorf("failed to run wmic process: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write process list output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat process list output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash process list output: %w", err)
	}

	manifest.AddItem("process_list_detailed.csv", stat.Size(), sha256Hex, false, stat.ModTime(), "process_list", "Detailed process information from wmic process")
	manifest.IncrementTotalFiles()

	// Also collect tasklist output with services
	outputPath2 := filepath.Join(outDir, "tasklist_services.txt")
	args2 := []string{"/svc"}
	output2, err := winutil.RunCommandWithOutput(ctx, "tasklist", args2)
	if err == nil {
		if err := os.WriteFile(outputPath2, output2, 0644); err == nil {
			if stat2, err := os.Stat(outputPath2); err == nil {
				if sha256Hex2, err := winutil.HashFile(outputPath2); err == nil {
					manifest.AddItem("tasklist_services.txt", stat2.Size(), sha256Hex2, false, stat2.ModTime(), "process_list", "Process list with services from tasklist /svc")
					manifest.IncrementTotalFiles()
				}
			}
		}
	}

	return nil
}

// collectHandleInformation collects handle information using PowerShell Get-Process.
func (w *WinMemoryProcess) collectHandleInformation(ctx context.Context, outDir string, manifest *MemoryProcessManifest) error {
	outputPath := filepath.Join(outDir, "process_handles.txt")

	// PowerShell script to get process handles
	psScript := `Get-Process | Select-Object Id, Name, Handles, WorkingSet, VirtualMemorySize, StartTime | Format-Table -AutoSize`
	args := []string{"-Command", psScript}
	output, err := winutil.RunCommandWithOutput(ctx, "powershell", args)
	if err != nil {
		return fmt.Errorf("failed to run PowerShell handles command: %w", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write handles output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat handles output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash handles output: %w", err)
	}

	manifest.AddItem("process_handles.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "handles", "Process handles information from PowerShell Get-Process")
	manifest.IncrementTotalFiles()

	return nil
}

// collectMemoryInformation collects system memory information.
func (w *WinMemoryProcess) collectMemoryInformation(ctx context.Context, outDir string, manifest *MemoryProcessManifest) error {
	outputPath := filepath.Join(outDir, "memory_info.csv")

	// Use wmic to get memory information
	args := []string{"computersystem", "get", "TotalPhysicalMemory", "/format:csv"}
	output, err := winutil.RunCommandWithOutput(ctx, "wmic", args)
	if err != nil {
		return fmt.Errorf("failed to run wmic computersystem: %w", err)
	}

	// Append OS memory info
	args2 := []string{"OS", "get", "TotalVirtualMemorySize,TotalVisibleMemorySize,FreePhysicalMemory,FreeVirtualMemory", "/format:csv"}
	output2, err := winutil.RunCommandWithOutput(ctx, "wmic", args2)
	if err == nil {
		output = append(output, []byte("\n--- OS Memory Information ---\n")...)
		output = append(output, output2...)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, output, 0644); err != nil {
		return fmt.Errorf("failed to write memory info output: %w", err)
	}

	// Get file info and add to manifest
	stat, err := os.Stat(outputPath)
	if err != nil {
		return fmt.Errorf("failed to stat memory info output: %w", err)
	}

	// Calculate hash of the output file
	sha256Hex, err := winutil.HashFile(outputPath)
	if err != nil {
		return fmt.Errorf("failed to hash memory info output: %w", err)
	}

	manifest.AddItem("memory_info.csv", stat.Size(), sha256Hex, false, stat.ModTime(), "memory_info", "System memory information from wmic")
	manifest.IncrementTotalFiles()

	return nil
}

// collectVirtualMemoryInfo collects information about virtual memory files (metadata only).
func (w *WinMemoryProcess) collectVirtualMemoryInfo(ctx context.Context, outDir string, manifest *MemoryProcessManifest, constraints *winutil.SizeConstraints) error {
	// Get system drive
	systemDrive := os.Getenv("SystemDrive")
	if systemDrive == "" {
		systemDrive = "C:"
	}

	// Check for virtual memory files and collect metadata
	virtualMemoryFiles := []struct {
		filename string
		desc     string
	}{
		{"pagefile.sys", "Windows virtual memory paging file"},
		{"swapfile.sys", "Windows compressed memory swap file"},
		{"hiberfil.sys", "Windows hibernation file"},
	}

	infoContent := "Virtual Memory Files Information:\n\n"
	
	for _, vmFile := range virtualMemoryFiles {
		filePath := filepath.Join(systemDrive+"\\", vmFile.filename)
		
		if stat, err := os.Stat(filePath); err == nil {
			manifest.IncrementTotalFiles()
			infoContent += fmt.Sprintf("File: %s\n", vmFile.filename)
			infoContent += fmt.Sprintf("Description: %s\n", vmFile.desc)
			infoContent += fmt.Sprintf("Size: %d bytes (%.2f GB)\n", stat.Size(), float64(stat.Size())/1024/1024/1024)
			infoContent += fmt.Sprintf("Modified: %s\n", stat.ModTime().Format(time.RFC3339))
			infoContent += fmt.Sprintf("Note: File not copied due to size constraints\n\n")
		} else {
			infoContent += fmt.Sprintf("File: %s\n", vmFile.filename)
			infoContent += fmt.Sprintf("Status: Not found or not accessible\n\n")
		}
	}

	// Write info file
	infoPath := filepath.Join(outDir, "virtual_memory_files_info.txt")
	if err := os.WriteFile(infoPath, []byte(infoContent), 0644); err != nil {
		return fmt.Errorf("failed to write virtual memory info: %w", err)
	}

	// Add info file to manifest
	if stat, err := os.Stat(infoPath); err == nil {
		if sha256Hex, err := winutil.HashFile(infoPath); err == nil {
			manifest.AddItem("virtual_memory_files_info.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "pagefile", "Virtual memory files metadata (files not copied due to size)")
		}
	}

	return nil
}