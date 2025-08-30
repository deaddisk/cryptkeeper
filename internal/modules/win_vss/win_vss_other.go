//go:build !windows

package win_vss

import (
	"context"
)

// WinVSS represents the Volume Shadow Copy Service collection module (no-op on non-Windows).
type WinVSS struct{}

// NewWinVSS creates a new Volume Shadow Copy Service collection module.
func NewWinVSS() *WinVSS {
	return &WinVSS{}
}

// Name returns the module's identifier.
func (w *WinVSS) Name() string {
	return "windows/vss"
}

// Collect is a no-op on non-Windows systems.
func (w *WinVSS) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}