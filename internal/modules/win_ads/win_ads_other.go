//go:build !windows

package win_ads

import (
	"context"
)

// WinADS represents the Alternate Data Streams collection module (no-op on non-Windows).
type WinADS struct{}

// NewWinADS creates a new Alternate Data Streams collection module.
func NewWinADS() *WinADS {
	return &WinADS{}
}

// Name returns the module's identifier.
func (w *WinADS) Name() string {
	return "windows/ads"
}

// Collect is a no-op on non-Windows systems.
func (w *WinADS) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}