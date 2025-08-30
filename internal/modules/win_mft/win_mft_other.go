//go:build !windows

package win_mft

import (
	"context"
)

// WinMFT represents the NTFS Master File Table collection module (no-op on non-Windows).
type WinMFT struct{}

// NewWinMFT creates a new NTFS Master File Table collection module.
func NewWinMFT() *WinMFT {
	return &WinMFT{}
}

// Name returns the module's identifier.
func (w *WinMFT) Name() string {
	return "windows/mft"
}

// Collect is a no-op on non-Windows systems.
func (w *WinMFT) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}