//go:build windows

package sysinfo

import (
	"syscall"
	"time"
)

// getUptime returns the system uptime in seconds and boot time for Windows systems.
// It uses GetTickCount64 to get the uptime in milliseconds.
func getUptime() (uptimeSeconds int64, bootTimeUTC string) {
	// Load kernel32.dll
	kernel32 := syscall.MustLoadDLL("kernel32.dll")
	defer kernel32.Release()

	// Get GetTickCount64 procedure
	getTickCount64 := kernel32.MustFindProc("GetTickCount64")

	// Call GetTickCount64
	ret, _, _ := getTickCount64.Call()
	
	// Convert milliseconds to seconds
	uptimeMs := int64(ret)
	uptimeSeconds = uptimeMs / 1000

	// Calculate boot time
	now := time.Now().UTC()
	bootTime := now.Add(-time.Duration(uptimeMs) * time.Millisecond)
	bootTimeUTC = bootTime.Format(time.RFC3339)

	return uptimeSeconds, bootTimeUTC
}

// Alternative implementation using syscall if the above doesn't work
func getUptimeAlternative() (uptimeSeconds int64, bootTimeUTC string) {
	// This is a fallback using direct syscall
	kernel32, err := syscall.LoadLibrary("kernel32.dll")
	if err != nil {
		return 0, ""
	}
	defer syscall.FreeLibrary(kernel32)

	proc, err := syscall.GetProcAddress(kernel32, "GetTickCount64")
	if err != nil {
		return 0, ""
	}

	ret, _, _ := syscall.Syscall(proc, 0, 0, 0, 0)
	uptimeMs := int64(ret)
	uptimeSeconds = uptimeMs / 1000

	now := time.Now().UTC()
	bootTime := now.Add(-time.Duration(uptimeMs) * time.Millisecond)
	bootTimeUTC = bootTime.Format(time.RFC3339)

	return uptimeSeconds, bootTimeUTC
}