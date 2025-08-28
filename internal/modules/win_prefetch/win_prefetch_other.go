//go:build !windows

package win_prefetch

import (
	"context"
)

// WinPrefetch represents the Windows prefetch collection module stub for non-Windows platforms.
type WinPrefetch struct{}

// NewWinPrefetch creates a new Windows prefetch collection module stub.
func NewWinPrefetch() *WinPrefetch {
	return &WinPrefetch{}
}

// Name returns the module's identifier.
func (w *WinPrefetch) Name() string {
	return "windows/prefetch"
}

// Collect is a no-op on non-Windows platforms and always returns nil.
func (w *WinPrefetch) Collect(ctx context.Context, outDir string) error {
	// This module only works on Windows, so it's a no-op on other platforms
	return nil
}