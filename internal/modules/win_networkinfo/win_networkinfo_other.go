//go:build !windows

package win_networkinfo

import (
	"context"
)

// WinNetworkInfo represents the Windows network information collection module (no-op on non-Windows).
type WinNetworkInfo struct{}

// NewWinNetworkInfo creates a new Windows network information collection module.
func NewWinNetworkInfo() *WinNetworkInfo {
	return &WinNetworkInfo{}
}

// Name returns the module's identifier.
func (w *WinNetworkInfo) Name() string {
	return "windows/networkinfo"
}

// Collect is a no-op on non-Windows systems.
func (w *WinNetworkInfo) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}