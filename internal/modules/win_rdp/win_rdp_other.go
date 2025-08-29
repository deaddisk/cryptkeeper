//go:build !windows

package win_rdp

import (
	"context"
)

// WinRDP represents the Windows RDP collection module (no-op on non-Windows).
type WinRDP struct{}

// NewWinRDP creates a new Windows RDP collection module.
func NewWinRDP() *WinRDP {
	return &WinRDP{}
}

// Name returns the module's identifier.
func (w *WinRDP) Name() string {
	return "windows/rdp"
}

// Collect is a no-op on non-Windows systems.
func (w *WinRDP) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}