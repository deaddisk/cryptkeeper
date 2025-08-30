//go:build !windows

package win_fileshares

import (
	"context"
)

// WinFileShares represents the Windows file shares collection module (no-op on non-Windows).
type WinFileShares struct{}

// NewWinFileShares creates a new Windows file shares collection module.
func NewWinFileShares() *WinFileShares {
	return &WinFileShares{}
}

// Name returns the module's identifier.
func (w *WinFileShares) Name() string {
	return "windows/fileshares"
}

// Collect is a no-op on non-Windows systems.
func (w *WinFileShares) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}