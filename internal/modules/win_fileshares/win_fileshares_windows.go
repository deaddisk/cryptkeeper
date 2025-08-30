//go:build windows

package win_fileshares

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinFileShares represents the Windows file shares collection module.
type WinFileShares struct{}

// NewWinFileShares creates a new Windows file shares collection module.
func NewWinFileShares() *WinFileShares {
	return &WinFileShares{}
}

// Name returns the module's identifier.
func (w *WinFileShares) Name() string {
	return "windows/fileshares"
}

// Collect gathers Windows file shares and permissions information.
func (w *WinFileShares) Collect(ctx context.Context, outDir string) error {
	// Create the windows/fileshares subdirectory
	sharesDir := filepath.Join(outDir, "windows", "fileshares")
	if err := winutil.EnsureDir(sharesDir); err != nil {
		return fmt.Errorf("failed to create fileshares directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewFileShareManifest(hostname)

	// Collect file shares information
	if err := w.collectFileShares(ctx, sharesDir, manifest); err != nil {
		manifest.AddError("file_shares", fmt.Sprintf("Failed to collect file shares: %v", err))
	}

	// Collect share permissions
	if err := w.collectSharePermissions(ctx, sharesDir, manifest); err != nil {
		manifest.AddError("share_permissions", fmt.Sprintf("Failed to collect share permissions: %v", err))
	}

	// Collect active sessions and open files
	if err := w.collectActiveSessions(ctx, sharesDir, manifest); err != nil {
		manifest.AddError("active_sessions", fmt.Sprintf("Failed to collect active sessions: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(sharesDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectFileShares collects information about configured file shares.
func (w *WinFileShares) collectFileShares(ctx context.Context, outDir string, manifest *FileShareManifest) error {
	outputPath := filepath.Join(outDir, "file_shares.txt")

	output := "Windows File Shares Information:\n\n"

	// Use net share command
	output += "=== Net Share ===\n"
	netShareCmd := []string{"/C", "net share"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", netShareCmd); err == nil {
		output += string(result)
		// Count shares (approximate by counting lines with '$' or regular shares)
		shareCount := strings.Count(string(result), "\n") - 3 // Subtract header lines
		if shareCount > 0 {
			manifest.SetSharesFound(shareCount)
		}
	} else {
		output += fmt.Sprintf("Error running net share: %v\n", err)
	}
	output += "\n"

	// Use WMIC to get detailed share information
	output += "=== WMIC Share Details ===\n"
	wmicShareCmd := []string{"/C", "wmic share get /format:list"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", wmicShareCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting WMIC share details: %v\n", err)
	}
	output += "\n"

	// Use PowerShell to get SMB shares (Windows 8+)
	output += "=== SMB Shares (PowerShell) ===\n"
	psScript := `Get-SmbShare | Format-List *`
	psCmd := []string{"-Command", psScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting SMB shares via PowerShell: %v\n", err)
		output += "Note: Get-SmbShare may not be available on older Windows versions.\n"
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write file shares info: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("file_shares.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "shares_info", "Windows file shares configuration and details")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectSharePermissions collects detailed share permissions information.
func (w *WinFileShares) collectSharePermissions(ctx context.Context, outDir string, manifest *FileShareManifest) error {
	outputPath := filepath.Join(outDir, "share_permissions.txt")

	output := "Share Permissions Information:\n\n"

	// Use PowerShell to get share access permissions
	output += "=== SMB Share Access (PowerShell) ===\n"
	psScript := `Get-SmbShareAccess | Format-List *`
	psCmd := []string{"-Command", psScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting SMB share access: %v\n", err)
	}
	output += "\n"

	// Get security descriptors for shares
	output += "=== Share Security Information ===\n"
	secScript := `Get-WmiObject -Class Win32_LogicalShareSecuritySetting | ForEach-Object { 
        Write-Output "Share: $($_.Name)";
        $_.GetSecurityDescriptor().Descriptor | Format-List *;
        Write-Output "---"
    }`
	secCmd := []string{"-Command", secScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", secCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting share security descriptors: %v\n", err)
	}
	output += "\n"

	// Use icacls for filesystem permissions on share paths (for default shares)
	output += "=== File System Permissions on Common Share Paths ===\n"
	commonShares := []string{
		"C:\\",
		"C:\\Windows",
		"C:\\Users",
		"C:\\Program Files",
	}

	for _, sharePath := range commonShares {
		if _, err := os.Stat(sharePath); err == nil {
			output += fmt.Sprintf("--- Permissions for %s ---\n", sharePath)
			icaclsCmd := []string{"/C", fmt.Sprintf("icacls \"%s\"", sharePath)}
			if result, err := winutil.RunCommandWithOutput(ctx, "cmd", icaclsCmd); err == nil {
				output += string(result)
			} else {
				output += fmt.Sprintf("Error getting permissions for %s: %v\n", sharePath, err)
			}
			output += "\n"
		}
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write share permissions: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("share_permissions.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "permissions", "Share permissions and security descriptors")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectActiveSessions collects information about active SMB sessions and open files.
func (w *WinFileShares) collectActiveSessions(ctx context.Context, outDir string, manifest *FileShareManifest) error {
	outputPath := filepath.Join(outDir, "active_sessions.txt")

	output := "Active SMB Sessions and Open Files:\n\n"

	// Use net session to show active sessions
	output += "=== Net Session ===\n"
	netSessionCmd := []string{"/C", "net session"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", netSessionCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting net sessions: %v\n", err)
	}
	output += "\n"

	// Use net file to show open files
	output += "=== Net File (Open Files) ===\n"
	netFileCmd := []string{"/C", "net file"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", netFileCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting open files: %v\n", err)
	}
	output += "\n"

	// Use PowerShell to get SMB sessions (Windows 8+)
	output += "=== SMB Sessions (PowerShell) ===\n"
	smbSessionScript := `Get-SmbSession | Format-List *`
	smbSessionCmd := []string{"-Command", smbSessionScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", smbSessionCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting SMB sessions: %v\n", err)
	}
	output += "\n"

	// Use PowerShell to get SMB open files
	output += "=== SMB Open Files (PowerShell) ===\n"
	smbFileScript := `Get-SmbOpenFile | Format-List *`
	smbFileCmd := []string{"-Command", smbFileScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", smbFileCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting SMB open files: %v\n", err)
	}
	output += "\n"

	// Use WMIC to get additional session information
	output += "=== WMIC Server Sessions ===\n"
	wmicSessionCmd := []string{"/C", "wmic serverconnection get /format:list"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", wmicSessionCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting WMIC server sessions: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write active sessions: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("active_sessions.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "sessions", "Active SMB sessions and open files information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}