//go:build !windows

package win_registry

import (
	"context"
)

// WinRegistry represents the Windows registry collection module stub for non-Windows platforms.
type WinRegistry struct{}

// NewWinRegistry creates a new Windows registry collection module stub.
func NewWinRegistry() *WinRegistry {
	return &WinRegistry{}
}

// Name returns the module's identifier.
func (w *WinRegistry) Name() string {
	return "windows/registry"
}

// Collect is a no-op on non-Windows platforms and always returns nil.
func (w *WinRegistry) Collect(ctx context.Context, outDir string) error {
	// This module only works on Windows, so it's a no-op on other platforms
	return nil
}