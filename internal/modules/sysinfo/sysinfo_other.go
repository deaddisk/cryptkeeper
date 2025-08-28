//go:build !linux && !windows && !darwin

package sysinfo

// getUptime returns zero values for unsupported operating systems.
// This provides a safe fallback that won't cause the module to fail.
func getUptime() (uptimeSeconds int64, bootTimeUTC string) {
	return 0, ""
}