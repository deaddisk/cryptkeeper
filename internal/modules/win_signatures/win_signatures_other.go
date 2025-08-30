//go:build !windows

package win_signatures

import (
	"context"
)

// WinSignatures represents the file signatures collection module (no-op on non-Windows).
type WinSignatures struct{}

// NewWinSignatures creates a new file signatures collection module.
func NewWinSignatures() *WinSignatures {
	return &WinSignatures{}
}

// Name returns the module's identifier.
func (w *WinSignatures) Name() string {
	return "windows/signatures"
}

// Collect is a no-op on non-Windows systems.
func (w *WinSignatures) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}