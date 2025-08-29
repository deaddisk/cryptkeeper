//go:build !windows

package win_wmi

import (
	"context"
)

// WinWMI represents the Windows WMI collection module (no-op on non-Windows).
type WinWMI struct{}

// NewWinWMI creates a new Windows WMI collection module.
func NewWinWMI() *WinWMI {
	return &WinWMI{}
}

// Name returns the module's identifier.
func (w *WinWMI) Name() string {
	return "windows/wmi"
}

// Collect is a no-op on non-Windows systems.
func (w *WinWMI) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}