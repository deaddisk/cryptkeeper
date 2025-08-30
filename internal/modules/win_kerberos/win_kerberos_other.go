//go:build !windows

package win_kerberos

import (
	"context"
)

// WinKerberos represents the Kerberos authentication collection module (no-op on non-Windows).
type WinKerberos struct{}

// NewWinKerberos creates a new Kerberos authentication collection module.
func NewWinKerberos() *WinKerberos {
	return &WinKerberos{}
}

// Name returns the module's identifier.
func (w *WinKerberos) Name() string {
	return "windows/kerberos"
}

// Collect is a no-op on non-Windows systems.
func (w *WinKerberos) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}