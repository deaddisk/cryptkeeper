//go:build !windows

package win_trustedinstaller

import (
	"context"
)

// WinTrustedInstaller represents the TrustedInstaller collection module (no-op on non-Windows).
type WinTrustedInstaller struct{}

// NewWinTrustedInstaller creates a new TrustedInstaller collection module.
func NewWinTrustedInstaller() *WinTrustedInstaller {
	return &WinTrustedInstaller{}
}

// Name returns the module's identifier.
func (w *WinTrustedInstaller) Name() string {
	return "windows/trustedinstaller"
}

// Collect is a no-op on non-Windows systems.
func (w *WinTrustedInstaller) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}