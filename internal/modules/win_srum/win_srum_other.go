//go:build !windows

package win_srum

import (
	"context"
)

// WinSRUM represents the Windows SRUM collection module (no-op on non-Windows).
type WinSRUM struct{}

// NewWinSRUM creates a new Windows SRUM collection module.
func NewWinSRUM() *WinSRUM {
	return &WinSRUM{}
}

// Name returns the module's identifier.
func (w *WinSRUM) Name() string {
	return "windows/srum"
}

// Collect is a no-op on non-Windows systems.
func (w *WinSRUM) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}