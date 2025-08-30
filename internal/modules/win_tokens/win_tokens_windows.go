//go:build windows

package win_tokens

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"cryptkeeper/internal/winutil"
)

// WinTokens represents the access tokens collection module.
type WinTokens struct{}

// NewWinTokens creates a new access tokens collection module.
func NewWinTokens() *WinTokens {
	return &WinTokens{}
}

// Name returns the module's identifier.
func (w *WinTokens) Name() string {
	return "windows/tokens"
}

// Collect gathers access tokens and privileges information.
func (w *WinTokens) Collect(ctx context.Context, outDir string) error {
	// Create the windows/tokens subdirectory
	tokensDir := filepath.Join(outDir, "windows", "tokens")
	if err := winutil.EnsureDir(tokensDir); err != nil {
		return fmt.Errorf("failed to create tokens directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewTokenManifest(hostname)

	// Collect access tokens information
	if err := w.collectAccessTokens(ctx, tokensDir, manifest); err != nil {
		manifest.AddError("access_tokens", fmt.Sprintf("Failed to collect access tokens: %v", err))
	}

	// Collect privileges information
	if err := w.collectPrivileges(ctx, tokensDir, manifest); err != nil {
		manifest.AddError("privileges", fmt.Sprintf("Failed to collect privileges: %v", err))
	}

	// Collect token groups and SIDs
	if err := w.collectTokenGroups(ctx, tokensDir, manifest); err != nil {
		manifest.AddError("token_groups", fmt.Sprintf("Failed to collect token groups: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(tokensDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectAccessTokens collects access token information for current process.
func (w *WinTokens) collectAccessTokens(ctx context.Context, outDir string, manifest *TokenManifest) error {
	outputPath := filepath.Join(outDir, "access_tokens.txt")

	output := "Access Tokens Information:\n\n"
	output += "Note: This collection focuses on token information accessible via standard commands.\n"
	output += "Detailed token extraction requires specialized tools and high privileges.\n\n"

	// Get current process token information
	output += "=== Current Process Token Information ===\n"
	whoamiCmd := []string{"/C", "whoami /all"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", whoamiCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting whoami /all: %v\n", err)
	}
	output += "\n"

	// Get process list with security contexts
	output += "=== Process Security Contexts ===\n"
	processCmd := []string{"/C", "wmic process get processid,name,executablepath,sessionid /format:table"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", processCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting process security contexts: %v\n", err)
	}
	output += "\n"

	// Use PowerShell to get more detailed token information
	output += "=== Process Token Details (PowerShell) ===\n"
	psScript := `Get-Process | Where-Object {$_.Id -eq $PID} | Select-Object Id, ProcessName, StartTime, @{Name="UserName";Expression={(Get-WmiObject -Class Win32_Process -Filter "ProcessId=$($_.Id)").GetOwner() | ForEach-Object {"$($_.Domain)\\$($_.User)"}}} | Format-List`
	psCmd := []string{"-Command", psScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting process token details: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write access tokens: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("access_tokens.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "access_tokens", "Access token information for current process")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectPrivileges collects privileges and user rights information.
func (w *WinTokens) collectPrivileges(ctx context.Context, outDir string, manifest *TokenManifest) error {
	outputPath := filepath.Join(outDir, "privileges.txt")

	output := "Privileges and User Rights Information:\n\n"

	// Get current process privileges
	output += "=== Current Process Privileges ===\n"
	privCmd := []string{"/C", "whoami /priv"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", privCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting current privileges: %v\n", err)
	}
	output += "\n"

	// Get user rights assignments from security policy
	output += "=== User Rights Assignments ===\n"
	output += "Note: Extracting security policy to temporary file...\n"
	secpolCmd := []string{"/C", "secedit /export /cfg temp_policy.inf /quiet && findstr /R /C:\"Se.*Privilege\" temp_policy.inf && del temp_policy.inf"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", secpolCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting user rights assignments: %v\n", err)
	}
	output += "\n"

	// Get token elevation information
	output += "=== Token Elevation Information ===\n"
	elevationScript := `
	$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
	$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
	Write-Output "Is Administrator: $isAdmin"
	
	$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
	Write-Output "Authentication Type: $($identity.AuthenticationType)"
	Write-Output "Is Anonymous: $($identity.IsAnonymous)"
	Write-Output "Is Authenticated: $($identity.IsAuthenticated)"
	Write-Output "Is Guest: $($identity.IsGuest)"
	Write-Output "Is System: $($identity.IsSystem)"
	Write-Output "Name: $($identity.Name)"
	Write-Output "Token: $($identity.Token)"
	`
	elevationCmd := []string{"-Command", elevationScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", elevationCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting token elevation info: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write privileges: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("privileges.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "privileges", "User privileges and rights assignments")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectTokenGroups collects token groups and SID information.
func (w *WinTokens) collectTokenGroups(ctx context.Context, outDir string, manifest *TokenManifest) error {
	outputPath := filepath.Join(outDir, "token_groups.txt")

	output := "Token Groups and SID Information:\n\n"

	// Get current user and group information
	output += "=== Current User and Groups ===\n"
	groupsCmd := []string{"/C", "whoami /groups"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", groupsCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting groups: %v\n", err)
	}
	output += "\n"

	// Get user SID information
	output += "=== User SID Information ===\n"
	sidCmd := []string{"/C", "whoami /user"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", sidCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting user SID: %v\n", err)
	}
	output += "\n"

	// Get local users and their SIDs
	output += "=== Local Users and SIDs ===\n"
	localUsersCmd := []string{"/C", "wmic useraccount get name,sid,fullname,disabled"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", localUsersCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting local users: %v\n", err)
	}
	output += "\n"

	// Get local groups and their SIDs
	output += "=== Local Groups and SIDs ===\n"
	localGroupsCmd := []string{"/C", "wmic group get name,sid,description"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", localGroupsCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting local groups: %v\n", err)
	}
	output += "\n"

	// Get detailed group membership using PowerShell
	output += "=== Detailed Group Membership (PowerShell) ===\n"
	groupScript := `
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	Write-Output "Current User: $($currentUser.Name)"
	Write-Output "Groups:"
	$currentUser.Groups | ForEach-Object {
		$group = $_.Translate([Security.Principal.NTAccount])
		Write-Output "  $group ($_)"
	}
	`
	groupPSCmd := []string{"-Command", groupScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", groupPSCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting detailed group membership: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write token groups: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("token_groups.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "token_groups", "Token groups and SID information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}