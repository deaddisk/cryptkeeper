//go:build darwin

package sysinfo

import (
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// getUptime returns the system uptime in seconds and boot time for macOS systems.
// It uses sysctl to get the kern.boottime.
func getUptime() (uptimeSeconds int64, bootTimeUTC string) {
	// Get boot time using sysctl kern.boottime
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return 0, ""
	}

	// Convert timeval to time.Time
	bootTime := time.Unix(tv.Sec, tv.Usec*1000).UTC()
	
	// Calculate uptime
	now := time.Now().UTC()
	uptime := now.Sub(bootTime)
	uptimeSeconds = int64(uptime.Seconds())
	
	bootTimeUTC = bootTime.Format(time.RFC3339)

	return uptimeSeconds, bootTimeUTC
}

// Alternative implementation using raw sysctl if the above doesn't work
func getUptimeAlternative() (uptimeSeconds int64, bootTimeUTC string) {
	// This implementation uses the raw sysctl syscall
	mib := []int32{1, 21} // CTL_KERN, KERN_BOOTTIME
	
	var tv unix.Timeval
	size := uintptr(unsafe.Sizeof(tv))
	
	_, _, errno := unix.Syscall6(
		unix.SYS___SYSCTL,
		uintptr(unsafe.Pointer(&mib[0])),
		uintptr(len(mib)),
		uintptr(unsafe.Pointer(&tv)),
		uintptr(unsafe.Pointer(&size)),
		0,
		0,
	)
	
	if errno != 0 {
		return 0, ""
	}
	
	bootTime := time.Unix(tv.Sec, tv.Usec*1000).UTC()
	now := time.Now().UTC()
	uptime := now.Sub(bootTime)
	uptimeSeconds = int64(uptime.Seconds())
	bootTimeUTC = bootTime.Format(time.RFC3339)

	return uptimeSeconds, bootTimeUTC
}