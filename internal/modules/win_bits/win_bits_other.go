//go:build !windows

package win_bits

import (
	"context"
)

// WinBITS represents the Windows BITS collection module (no-op on non-Windows).
type WinBITS struct{}

// NewWinBITS creates a new Windows BITS collection module.
func NewWinBITS() *WinBITS {
	return &WinBITS{}
}

// Name returns the module's identifier.
func (w *WinBITS) Name() string {
	return "windows/bits"
}

// Collect is a no-op on non-Windows systems.
func (w *WinBITS) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}