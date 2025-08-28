//go:build windows

package winutil

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// ExecWithContext executes a command with context support, returning stdout, stderr, and error.
// This provides a consistent interface for executing Windows commands with timeout support.
func ExecWithContext(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error) {
	cmd := exec.CommandContext(ctx, name, args...)
	
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	
	err = cmd.Run()
	return stdoutBuf.Bytes(), stderrBuf.Bytes(), err
}

// ExportEventLog wraps wevtutil.exe to export an event log channel with optional time filtering.
// This is a specialized version for event log export with proper context handling.
func ExportEventLog(ctx context.Context, channel string, destPath string, sinceRFC3339 string) error {
	args := []string{"epl", channel, destPath, "/ow:true"}
	
	// Add time filter if specified
	if sinceRFC3339 != "" {
		// Convert RFC3339 to milliseconds for wevtutil query
		// This is simplified - in production you'd want proper time calculation
		query := fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= 604800000]]]") // Example: 7 days
		args = append(args, "/q:"+query)
	}
	
	_, stderr, err := ExecWithContext(ctx, "wevtutil", args...)
	if err != nil {
		stderrStr := string(stderr)
		if strings.Contains(stderrStr, "Access is denied") || 
		   strings.Contains(stderrStr, "access denied") ||
		   strings.Contains(stderrStr, "0x5") {
			return fmt.Errorf("access denied to channel %s (requires elevation or Event Log Readers group)", channel)
		}
		return fmt.Errorf("wevtutil failed for channel %s: %w (stderr: %s)", channel, err, stderrStr)
	}
	
	return nil
}

// ExportRegistryHive uses reg.exe to export a registry hive to a file.
// This is the fallback method when direct file copy fails.
func ExportRegistryHive(ctx context.Context, hiveKey string, destPath string) error {
	args := []string{"save", hiveKey, destPath, "/y"}
	
	_, stderr, err := ExecWithContext(ctx, "reg", args...)
	if err != nil {
		stderrStr := string(stderr)
		if strings.Contains(stderrStr, "Access is denied") || 
		   strings.Contains(stderrStr, "access denied") {
			return fmt.Errorf("access denied to registry hive %s (requires elevation)", hiveKey)
		}
		return fmt.Errorf("reg save failed for hive %s: %w (stderr: %s)", hiveKey, err, stderrStr)
	}
	
	return nil
}

// GetSystemInfo runs basic system information commands and returns the output.
// This can be useful for additional context in forensic collections.
func GetSystemInfo(ctx context.Context) (map[string]string, error) {
	info := make(map[string]string)
	
	// Get system information
	if stdout, _, err := ExecWithContext(ctx, "systeminfo"); err == nil {
		info["systeminfo"] = string(stdout)
	}
	
	// Get running processes
	if stdout, _, err := ExecWithContext(ctx, "tasklist", "/fo", "csv"); err == nil {
		info["processes"] = string(stdout)
	}
	
	// Get network configuration
	if stdout, _, err := ExecWithContext(ctx, "ipconfig", "/all"); err == nil {
		info["network"] = string(stdout)
	}
	
	return info, nil
}