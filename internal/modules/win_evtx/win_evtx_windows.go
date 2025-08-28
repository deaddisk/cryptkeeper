//go:build windows

package win_evtx

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// WinEvtx represents the Windows Event Log collection module.
type WinEvtx struct {
	sinceTime string // RFC3339 timestamp for filtering (optional)
}

// NewWinEvtx creates a new Windows Event Log collection module.
func NewWinEvtx() *WinEvtx {
	return &WinEvtx{}
}

// SetSinceTime configures the time filter for event log collection.
func (w *WinEvtx) SetSinceTime(sinceRFC3339 string) {
	w.sinceTime = sinceRFC3339
}

// Name returns the module's identifier.
func (w *WinEvtx) Name() string {
	return "windows/evtx"
}

// ChannelInfo represents information about an event log channel to collect.
type ChannelInfo struct {
	Channel  string
	FileName string
}

// channels defines the event log channels to collect.
var channels = []ChannelInfo{
	{"Security", "Security.evtx"},
	{"System", "System.evtx"},
	{"Microsoft-Windows-PowerShell/Operational", "Microsoft-Windows-PowerShell%4Operational.evtx"},
}

// Collect exports Windows Event Logs and creates a manifest.
func (w *WinEvtx) Collect(ctx context.Context, outDir string) error {
	// Create the windows/evtx subdirectory
	evtxDir := filepath.Join(outDir, "windows", "evtx")
	if err := os.MkdirAll(evtxDir, 0755); err != nil {
		return fmt.Errorf("failed to create evtx directory: %w", err)
	}

	// Get hostname for manifest
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	var channelFiles []ChannelFile
	var errors []string

	// Calculate since time in milliseconds if provided
	sinceMs := int64(0)
	if w.sinceTime != "" {
		if since, err := time.Parse(time.RFC3339, w.sinceTime); err == nil {
			now := time.Now().UTC()
			duration := now.Sub(since)
			sinceMs = duration.Milliseconds()
			if sinceMs < 0 {
				sinceMs = 0 // Clamp negative values
			}
		}
	}

	// Process each channel
	for _, channel := range channels {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		outputPath := filepath.Join(evtxDir, channel.FileName)
		
		// Try to export the channel
		err := w.exportChannel(ctx, channel.Channel, outputPath, sinceMs)
		if err != nil {
			// Try fallback copy method
			if copyErr := w.fallbackCopy(channel.Channel, outputPath); copyErr != nil {
				// Both methods failed
				errMsg := fmt.Sprintf("%s (export: %v, copy: %v)", channel.Channel, err, copyErr)
				errors = append(errors, errMsg)
				continue
			}
		}

		// Check if file exists and compute hash
		if _, err := os.Stat(outputPath); err == nil {
			hash, size, hashErr := ComputeFileSHA256(outputPath)
			if hashErr != nil {
				errors = append(errors, fmt.Sprintf("%s: failed to hash file: %v", channel.Channel, hashErr))
				continue
			}

			channelFiles = append(channelFiles, ChannelFile{
				Channel: channel.Channel,
				File:    channel.FileName,
				Size:    size,
				SHA256:  hash,
			})
		} else {
			errors = append(errors, fmt.Sprintf("%s: file not created", channel.Channel))
		}
	}

	// Write manifest
	manifestPath := filepath.Join(evtxDir, "manifest.json")
	if err := WriteManifest(manifestPath, channelFiles, hostname); err != nil {
		errors = append(errors, fmt.Sprintf("manifest: %v", err))
	}

	// Return error if any channels failed
	if len(errors) > 0 {
		return fmt.Errorf("WinEvtx: failed for channels: %s", strings.Join(errors, ", "))
	}

	return nil
}

// exportChannel uses wevtutil.exe to export an event log channel.
func (w *WinEvtx) exportChannel(ctx context.Context, channel, outputPath string, sinceMs int64) error {
	args := []string{"epl", channel, outputPath, "/ow:true"}
	
	// Add time filter if specified
	if sinceMs > 0 {
		query := fmt.Sprintf("*[System[TimeCreated[timediff(@SystemTime) <= %d]]]", sinceMs)
		args = append(args, "/q:"+query)
	}

	cmd := exec.CommandContext(ctx, "wevtutil", args...)
	
	// Capture stderr for error reporting
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check for common access denied errors
		outputStr := string(output)
		if strings.Contains(outputStr, "Access is denied") || 
		   strings.Contains(outputStr, "access denied") ||
		   strings.Contains(outputStr, "0x5") {
			return getElevationRequiredError(channel)
		}
		return fmt.Errorf("wevtutil failed: %w (output: %s)", err, outputStr)
	}

	return nil
}

// fallbackCopy attempts to copy the raw event log file directly.
func (w *WinEvtx) fallbackCopy(channel, outputPath string) error {
	sourcePath, exists := getChannelLogFilePath(channel)
	if !exists {
		return fmt.Errorf("unknown channel mapping for %s", channel)
	}

	// Check if source file exists
	if _, err := os.Stat(sourcePath); os.IsNotExist(err) {
		return fmt.Errorf("source log file does not exist: %s", sourcePath)
	}

	// Attempt tolerant copy
	err := copyFileWithTolerantSharing(sourcePath, outputPath)
	if err != nil {
		// Check for access denied and provide helpful error
		if strings.Contains(err.Error(), "Access is denied") || 
		   strings.Contains(err.Error(), "access denied") {
			return getElevationRequiredError(channel)
		}
		return fmt.Errorf("file copy failed: %w", err)
	}

	return nil
}