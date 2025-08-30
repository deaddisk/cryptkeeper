//go:build !windows

package win_tokens

import (
	"context"
)

// WinTokens represents the access tokens collection module (no-op on non-Windows).
type WinTokens struct{}

// NewWinTokens creates a new access tokens collection module.
func NewWinTokens() *WinTokens {
	return &WinTokens{}
}

// Name returns the module's identifier.
func (w *WinTokens) Name() string {
	return "windows/tokens"
}

// Collect is a no-op on non-Windows systems.
func (w *WinTokens) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}