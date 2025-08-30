//go:build !windows

package win_certificates

import (
	"context"
)

// WinCertificates represents the certificates collection module (no-op on non-Windows).
type WinCertificates struct{}

// NewWinCertificates creates a new certificates collection module.
func NewWinCertificates() *WinCertificates {
	return &WinCertificates{}
}

// Name returns the module's identifier.
func (w *WinCertificates) Name() string {
	return "windows/certificates"
}

// Collect is a no-op on non-Windows systems.
func (w *WinCertificates) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}