//go:build !windows

package win_logon

import (
	"context"
)

// WinLogon represents the logon sessions collection module (no-op on non-Windows).
type WinLogon struct{}

// NewWinLogon creates a new logon sessions collection module.
func NewWinLogon() *WinLogon {
	return &WinLogon{}
}

// Name returns the module's identifier.
func (w *WinLogon) Name() string {
	return "windows/logon"
}

// Collect is a no-op on non-Windows systems.
func (w *WinLogon) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}