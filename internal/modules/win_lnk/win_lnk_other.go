//go:build !windows

package win_lnk

import (
	"context"
)

// WinLNK represents the Windows shortcut files collection module (no-op on non-Windows).
type WinLNK struct{}

// NewWinLNK creates a new Windows shortcut files collection module.
func NewWinLNK() *WinLNK {
	return &WinLNK{}
}

// Name returns the module's identifier.
func (w *WinLNK) Name() string {
	return "windows/lnk"
}

// Collect is a no-op on non-Windows systems.
func (w *WinLNK) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}