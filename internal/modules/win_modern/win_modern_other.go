//go:build !windows

package win_modern

import (
	"context"
)

// WinModern represents the Windows modern artifacts collection module (no-op on non-Windows).
type WinModern struct{}

// NewWinModern creates a new Windows modern artifacts collection module.
func NewWinModern() *WinModern {
	return &WinModern{}
}

// Name returns the module's identifier.
func (w *WinModern) Name() string {
	return "windows/modern"
}

// Collect is a no-op on non-Windows systems.
func (w *WinModern) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}