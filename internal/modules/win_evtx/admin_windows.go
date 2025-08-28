//go:build windows

package win_evtx

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	advapi32                     = windows.NewLazySystemDLL("advapi32.dll")
	procGetTokenInformation      = advapi32.NewProc("GetTokenInformation")
	procOpenProcessToken         = advapi32.NewProc("OpenProcessToken")
	procAllocateAndInitializeSid = advapi32.NewProc("AllocateAndInitializeSid")
	procCheckTokenMembership     = advapi32.NewProc("CheckTokenMembership")
	procFreeSid                  = advapi32.NewProc("FreeSid")
)

const (
	tokenElevationType = 18
	tokenElevation     = 20

	tokenElevationTypeLimited = 1
	tokenElevationTypeFull    = 2
	tokenElevationTypeDefault = 3

	securityNtAuthority    = 5
	securityBuiltinDomainRid = 0x20
	domainAliasSidAdmins     = 0x220

	tokenQuery = 0x0008
)

// isAdmin checks if the current process is running with administrator privileges.
// It returns true if elevated, false otherwise.
func isAdmin() bool {
	// Method 1: Try elevation token check
	if elevated, err := checkTokenElevation(); err == nil {
		return elevated
	}

	// Method 2: Fallback to group membership check
	return checkAdministratorGroupMembership()
}

// checkTokenElevation checks the token elevation status.
func checkTokenElevation() (bool, error) {
	currentProcess := windows.CurrentProcess()
	
	var token windows.Token
	err := windows.OpenProcessToken(currentProcess, tokenQuery, &token)
	if err != nil {
		return false, fmt.Errorf("failed to open process token: %w", err)
	}
	defer token.Close()

	// Check if the token is elevated
	var elevation uint32
	var returnLength uint32
	
	r1, _, err := procGetTokenInformation.Call(
		uintptr(token),
		tokenElevation,
		uintptr(unsafe.Pointer(&elevation)),
		unsafe.Sizeof(elevation),
		uintptr(unsafe.Pointer(&returnLength)),
	)
	
	if r1 == 0 {
		return false, fmt.Errorf("GetTokenInformation failed: %w", err)
	}

	return elevation != 0, nil
}

// checkAdministratorGroupMembership checks if the current user is in the Administrators group.
func checkAdministratorGroupMembership() bool {
	var sid uintptr
	
	// Create SID for BUILTIN\Administrators
	ntAuthority := [6]byte{0, 0, 0, 0, 0, securityNtAuthority}
	r1, _, _ := procAllocateAndInitializeSid.Call(
		uintptr(unsafe.Pointer(&ntAuthority[0])),
		2, // Sub authority count
		securityBuiltinDomainRid,
		domainAliasSidAdmins,
		0, 0, 0, 0, 0, 0, // Remaining sub authorities (unused)
		uintptr(unsafe.Pointer(&sid)),
	)
	
	if r1 == 0 {
		return false
	}
	defer procFreeSid.Call(sid)

	var isMember uint32
	r1, _, _ = procCheckTokenMembership.Call(
		0, // Use current thread token
		sid,
		uintptr(unsafe.Pointer(&isMember)),
	)
	
	if r1 == 0 {
		return false
	}

	return isMember != 0
}

// getElevationRequiredError returns an appropriate error message when elevation is required.
func getElevationRequiredError(channel string) error {
	if isAdmin() {
		return fmt.Errorf("access denied to channel %s (even with elevation - may require Event Log Readers group)", channel)
	}
	return fmt.Errorf("access denied to channel %s (run elevated or add user to Event Log Readers group)", channel)
}