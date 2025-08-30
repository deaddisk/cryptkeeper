//go:build !windows

package win_usn

import (
	"context"
)

// WinUSN represents the NTFS USN Journal collection module (no-op on non-Windows).
type WinUSN struct{}

// NewWinUSN creates a new NTFS USN Journal collection module.
func NewWinUSN() *WinUSN {
	return &WinUSN{}
}

// Name returns the module's identifier.
func (w *WinUSN) Name() string {
	return "windows/usn"
}

// Collect is a no-op on non-Windows systems.
func (w *WinUSN) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}