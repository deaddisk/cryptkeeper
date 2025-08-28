//go:build !windows

package win_jumplists

import (
	"context"
)

// WinJumpLists represents the Windows jump lists collection module stub for non-Windows platforms.
type WinJumpLists struct{}

// NewWinJumpLists creates a new Windows jump lists collection module stub.
func NewWinJumpLists() *WinJumpLists {
	return &WinJumpLists{}
}

// Name returns the module's identifier.
func (w *WinJumpLists) Name() string {
	return "windows/jumplists"
}

// Collect is a no-op on non-Windows platforms and always returns nil.
func (w *WinJumpLists) Collect(ctx context.Context, outDir string) error {
	// This module only works on Windows, so it's a no-op on other platforms
	return nil
}