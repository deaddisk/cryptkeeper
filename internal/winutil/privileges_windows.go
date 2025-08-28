//go:build windows

// Package winutil provides Windows-specific utilities for cryptkeeper.
package winutil

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	seBackupPrivilege  = "SeBackupPrivilege"
	seRestorePrivilege = "SeRestorePrivilege"
)

// EnableBackupRestorePrivileges attempts to enable SeBackupPrivilege and SeRestorePrivilege
// for the current process. These privileges are required for accessing locked system files
// and registry hives.
func EnableBackupRestorePrivileges() error {
	// Get current process token
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &token)
	if err != nil {
		return fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()

	// Enable SeBackupPrivilege
	if err := enablePrivilege(token, seBackupPrivilege); err != nil {
		return fmt.Errorf("failed to enable %s: %w", seBackupPrivilege, err)
	}

	// Enable SeRestorePrivilege
	if err := enablePrivilege(token, seRestorePrivilege); err != nil {
		return fmt.Errorf("failed to enable %s: %w", seRestorePrivilege, err)
	}

	return nil
}

// enablePrivilege enables a specific privilege for the given token.
func enablePrivilege(token windows.Token, privilegeName string) error {
	// Look up the privilege LUID
	var luid windows.LUID
	err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privilegeName), &luid)
	if err != nil {
		return fmt.Errorf("failed to lookup privilege %s: %w", privilegeName, err)
	}

	// Build TOKEN_PRIVILEGES structure
	privileges := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{
			{
				Luid:       luid,
				Attributes: windows.SE_PRIVILEGE_ENABLED,
			},
		},
	}

	// Adjust token privileges
	err = windows.AdjustTokenPrivileges(token, false, &privileges, 0, nil, nil)
	if err != nil {
		return fmt.Errorf("failed to adjust token privileges: %w", err)
	}

	// Check if the privilege was actually granted
	// ERROR_NOT_ALL_ASSIGNED indicates partial success
	if windows.GetLastError() == windows.ERROR_NOT_ALL_ASSIGNED {
		return fmt.Errorf("privilege %s not granted (insufficient rights)", privilegeName)
	}

	return nil
}

// CheckPrivileges returns information about whether backup/restore privileges are available.
func CheckPrivileges() (backupEnabled, restoreEnabled bool) {
	var token windows.Token
	err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &token)
	if err != nil {
		return false, false
	}
	defer token.Close()

	backupEnabled = hasPrivilege(token, seBackupPrivilege)
	restoreEnabled = hasPrivilege(token, seRestorePrivilege)

	return backupEnabled, restoreEnabled
}

// hasPrivilege checks if a specific privilege is available in the token.
func hasPrivilege(token windows.Token, privilegeName string) bool {
	var luid windows.LUID
	err := windows.LookupPrivilegeValue(nil, windows.StringToUTF16Ptr(privilegeName), &luid)
	if err != nil {
		return false
	}

	// Get token privileges
	var tokenPrivs *windows.Tokenprivileges
	var returnLength uint32

	// First call to get the required buffer size
	windows.GetTokenInformation(token, windows.TokenPrivileges, (*byte)(unsafe.Pointer(tokenPrivs)), 0, &returnLength)

	// Allocate buffer and get the actual privileges
	buffer := make([]byte, returnLength)
	err = windows.GetTokenInformation(token, windows.TokenPrivileges, &buffer[0], returnLength, &returnLength)
	if err != nil {
		return false
	}

	tokenPrivs = (*windows.Tokenprivileges)(unsafe.Pointer(&buffer[0]))

	// Search for our privilege
	for i := uint32(0); i < tokenPrivs.PrivilegeCount; i++ {
		privilege := (*windows.LUIDAndAttributes)(unsafe.Pointer(uintptr(unsafe.Pointer(&tokenPrivs.Privileges[0])) + uintptr(i)*unsafe.Sizeof(tokenPrivs.Privileges[0])))
		if privilege.Luid.LowPart == luid.LowPart && privilege.Luid.HighPart == luid.HighPart {
			return (privilege.Attributes & windows.SE_PRIVILEGE_ENABLED) != 0
		}
	}

	return false
}