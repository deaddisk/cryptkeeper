//go:build linux

package sysinfo

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// getUptime returns the system uptime in seconds and boot time for Linux systems.
// It reads from /proc/uptime which contains uptime and idle time as floating point seconds.
func getUptime() (uptimeSeconds int64, bootTimeUTC string) {
	// Read /proc/uptime
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0, ""
	}

	// Parse the first float (uptime in seconds)
	fields := strings.Fields(string(data))
	if len(fields) < 1 {
		return 0, ""
	}

	uptime, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, ""
	}

	uptimeSeconds = int64(uptime)
	
	// Calculate boot time
	now := time.Now().UTC()
	bootTime := now.Add(-time.Duration(uptimeSeconds) * time.Second)
	bootTimeUTC = bootTime.Format(time.RFC3339)

	return uptimeSeconds, bootTimeUTC
}