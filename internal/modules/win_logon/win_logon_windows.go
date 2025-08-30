//go:build windows

package win_logon

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"cryptkeeper/internal/winutil"
)

// WinLogon represents the logon sessions collection module.
type WinLogon struct{}

// NewWinLogon creates a new logon sessions collection module.
func NewWinLogon() *WinLogon {
	return &WinLogon{}
}

// Name returns the module's identifier.
func (w *WinLogon) Name() string {
	return "windows/logon"
}

// Collect gathers logon sessions and authentication history information.
func (w *WinLogon) Collect(ctx context.Context, outDir string) error {
	// Create the windows/logon subdirectory
	logonDir := filepath.Join(outDir, "windows", "logon")
	if err := winutil.EnsureDir(logonDir); err != nil {
		return fmt.Errorf("failed to create logon directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Create manifest
	manifest := NewLogonManifest(hostname)

	// Collect logon sessions
	if err := w.collectLogonSessions(ctx, logonDir, manifest); err != nil {
		manifest.AddError("logon_sessions", fmt.Sprintf("Failed to collect logon sessions: %v", err))
	}

	// Collect authentication history
	if err := w.collectAuthHistory(ctx, logonDir, manifest); err != nil {
		manifest.AddError("auth_history", fmt.Sprintf("Failed to collect auth history: %v", err))
	}

	// Collect login events from registry
	if err := w.collectLoginEvents(ctx, logonDir, manifest); err != nil {
		manifest.AddError("login_events", fmt.Sprintf("Failed to collect login events: %v", err))
	}

	// Write manifest
	manifestPath := filepath.Join(logonDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

// collectLogonSessions collects current logon sessions information.
func (w *WinLogon) collectLogonSessions(ctx context.Context, outDir string, manifest *LogonManifest) error {
	outputPath := filepath.Join(outDir, "logon_sessions.txt")

	output := "Logon Sessions Information:\n\n"

	// Use quser to show current user sessions
	output += "=== Current User Sessions (quser) ===\n"
	quserCmd := []string{"/C", "quser"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", quserCmd); err == nil {
		output += string(result)
		// Count active sessions
		sessionCount := strings.Count(string(result), "\n") - 1 // Subtract header
		if sessionCount > 0 {
			manifest.SetActiveSessionsFound(sessionCount)
		}
	} else {
		output += fmt.Sprintf("Error running quser: %v\n", err)
	}
	output += "\n"

	// Use query session to get detailed session information
	output += "=== Detailed Session Information (query session) ===\n"
	queryCmd := []string{"/C", "query session"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", queryCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error running query session: %v\n", err)
	}
	output += "\n"

	// Get currently logged on users using WMIC
	output += "=== Logged On Users (WMIC) ===\n"
	wmicCmd := []string{"/C", "wmic computersystem get username"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", wmicCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting logged on users: %v\n", err)
	}
	output += "\n"

	// Get session information using PowerShell
	output += "=== Session Information (PowerShell) ===\n"
	psScript := `Get-WmiObject -Class Win32_LogonSession | Select-Object LogonId, LogonType, StartTime, AuthenticationPackage | Format-Table -AutoSize`
	psCmd := []string{"-Command", psScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", psCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting session info via PowerShell: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write logon sessions: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("logon_sessions.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "logon_sessions", "Current logon sessions and user information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectAuthHistory collects authentication history and cached credentials info.
func (w *WinLogon) collectAuthHistory(ctx context.Context, outDir string, manifest *LogonManifest) error {
	outputPath := filepath.Join(outDir, "auth_history.txt")

	output := "Authentication History and Cached Credentials:\n\n"

	// Get cached domain credentials count
	output += "=== Cached Domain Logons ===\n"
	cachedCmd := []string{"query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "/v", "CachedLogonsCount"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", cachedCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting cached logons count: %v\n", err)
	}
	output += "\n"

	// Get winlogon settings
	output += "=== Winlogon Configuration ===\n"
	winlogonCmd := []string{"query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "/s"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", winlogonCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting winlogon config: %v\n", err)
	}
	output += "\n"

	// Get credential manager information
	output += "=== Credential Manager ===\n"
	credCmd := []string{"/C", "cmdkey /list"}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", credCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting credential manager: %v\n", err)
	}
	output += "\n"

	// Get authentication packages configuration
	output += "=== Authentication Packages ===\n"
	authPkgKey := "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
	authCmd := []string{"query", authPkgKey, "/v", "Authentication Packages"}
	if result, err := winutil.RunCommandWithOutput(ctx, "reg", authCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting auth packages: %v\n", err)
	}
	output += "\n"

	// Get last login information from registry
	output += "=== Last Login Information ===\n"
	lastLoginScript := `Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI" -ErrorAction SilentlyContinue | Format-List *`
	lastLoginCmd := []string{"-Command", lastLoginScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", lastLoginCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting last login info: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write auth history: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("auth_history.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "auth_history", "Authentication history and cached credentials information")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}

// collectLoginEvents collects login events and security audit information.
func (w *WinLogon) collectLoginEvents(ctx context.Context, outDir string, manifest *LogonManifest) error {
	outputPath := filepath.Join(outDir, "login_events.txt")

	output := "Login Events and Security Audit Information:\n\n"
	output += "Note: Detailed login events are typically found in Windows Event Logs.\n"
	output += "This collection focuses on configuration and recent login artifacts.\n\n"

	// Get event log configuration for security events
	output += "=== Security Event Log Configuration ===\n"
	secLogScript := `Get-WinEvent -ListLog Security | Format-List *`
	secLogCmd := []string{"-Command", secLogScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", secLogCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting security log config: %v\n", err)
	}
	output += "\n"

	// Get recent logon events (if accessible)
	output += "=== Recent Logon Events (Last 10) ===\n"
	recentLogonScript := `Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 10 -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap`
	recentLogonCmd := []string{"-Command", recentLogonScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", recentLogonCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting recent logon events: %v\n", err)
		output += "Note: May require administrator privileges to access Security event log.\n"
	}
	output += "\n"

	// Get failed logon events
	output += "=== Recent Failed Logon Events (Last 10) ===\n"
	failedLogonScript := `Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10 -ErrorAction SilentlyContinue | Format-Table TimeCreated, Id, LevelDisplayName, Message -Wrap`
	failedLogonCmd := []string{"-Command", failedLogonScript}
	if result, err := winutil.RunCommandWithOutput(ctx, "powershell", failedLogonCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting failed logon events: %v\n", err)
	}
	output += "\n"

	// Get audit policy configuration
	output += "=== Audit Policy Configuration ===\n"
	auditCmd := []string{"/C", "auditpol /get /category:\"Logon/Logoff\""}
	if result, err := winutil.RunCommandWithOutput(ctx, "cmd", auditCmd); err == nil {
		output += string(result)
	} else {
		output += fmt.Sprintf("Error getting audit policy: %v\n", err)
	}

	// Write output to file
	if err := os.WriteFile(outputPath, []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write login events: %w", err)
	}

	// Add to manifest
	if stat, err := os.Stat(outputPath); err == nil {
		if sha256Hex, err := winutil.HashFile(outputPath); err == nil {
			manifest.AddItem("login_events.txt", stat.Size(), sha256Hex, false, stat.ModTime(), "login_events", "Login events and security audit configuration")
			manifest.IncrementTotalFiles()
		}
	}

	return nil
}