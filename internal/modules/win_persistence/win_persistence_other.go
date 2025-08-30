//go:build !windows

package win_persistence

import (
	"context"
)

// WinPersistence represents the Windows persistence artifacts collection module (no-op on non-Windows).
type WinPersistence struct{}

// NewWinPersistence creates a new Windows persistence artifacts collection module.
func NewWinPersistence() *WinPersistence {
	return &WinPersistence{}
}

// Name returns the module's identifier.
func (w *WinPersistence) Name() string {
	return "windows/persistence"
}

// Collect is a no-op on non-Windows systems.
func (w *WinPersistence) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}