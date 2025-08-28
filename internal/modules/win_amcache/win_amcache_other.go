//go:build !windows

package win_amcache

import (
	"context"
)

// WinAmcache represents the Windows Amcache collection module stub for non-Windows platforms.
type WinAmcache struct{}

// NewWinAmcache creates a new Windows Amcache collection module stub.
func NewWinAmcache() *WinAmcache {
	return &WinAmcache{}
}

// Name returns the module's identifier.
func (w *WinAmcache) Name() string {
	return "windows/amcache"
}

// Collect is a no-op on non-Windows platforms and always returns nil.
func (w *WinAmcache) Collect(ctx context.Context, outDir string) error {
	// This module only works on Windows, so it's a no-op on other platforms
	return nil
}