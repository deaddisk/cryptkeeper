//go:build !windows

package win_lsa

import (
	"context"
)

// WinLSA represents the LSA Secrets collection module (no-op on non-Windows).
type WinLSA struct{}

// NewWinLSA creates a new LSA Secrets collection module.
func NewWinLSA() *WinLSA {
	return &WinLSA{}
}

// Name returns the module's identifier.
func (w *WinLSA) Name() string {
	return "windows/lsa"
}

// Collect is a no-op on non-Windows systems.
func (w *WinLSA) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}