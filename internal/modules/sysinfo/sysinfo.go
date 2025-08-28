// Package sysinfo provides system information collection for cryptkeeper.
package sysinfo

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"time"
)

// SysInfo represents the system information module.
type SysInfo struct{}

// NewSysInfo creates a new SysInfo module instance.
func NewSysInfo() *SysInfo {
	return &SysInfo{}
}

// Name returns the module's identifier.
func (s *SysInfo) Name() string {
	return "sysinfo"
}

// SystemInfo represents the structure of collected system information.
type SystemInfo struct {
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	Hostname      string `json:"hostname"`
	TimeUTC       string `json:"time_utc"`
	UptimeSeconds int64  `json:"uptime_seconds"`
	BootTimeUTC   string `json:"boot_time_utc"`
}

// Collect gathers system information and writes it to a JSON file in the output directory.
func (s *SysInfo) Collect(ctx context.Context, outDir string) error {
	// Get hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	// Get current time
	now := time.Now().UTC()

	// Get uptime information (OS-specific implementation)
	uptimeSeconds, bootTime := getUptime()

	// Create system info structure
	sysInfo := SystemInfo{
		OS:            runtime.GOOS,
		Arch:          runtime.GOARCH,
		Hostname:      hostname,
		TimeUTC:       now.Format(time.RFC3339),
		UptimeSeconds: uptimeSeconds,
		BootTimeUTC:   bootTime,
	}

	// Marshal to JSON with pretty formatting
	jsonData, err := json.MarshalIndent(sysInfo, "", "  ")
	if err != nil {
		return err
	}

	// Write to output file
	outputPath := filepath.Join(outDir, "sysinfo.json")
	return os.WriteFile(outputPath, jsonData, 0644)
}