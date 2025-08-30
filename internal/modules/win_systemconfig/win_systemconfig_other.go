//go:build !windows

package win_systemconfig

import (
	"context"
)

// WinSystemConfig represents the Windows system configuration collection module (no-op on non-Windows).
type WinSystemConfig struct{}

// NewWinSystemConfig creates a new Windows system configuration collection module.
func NewWinSystemConfig() *WinSystemConfig {
	return &WinSystemConfig{}
}

// Name returns the module's identifier.
func (w *WinSystemConfig) Name() string {
	return "windows/systemconfig"
}

// Collect is a no-op on non-Windows systems.
func (w *WinSystemConfig) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}