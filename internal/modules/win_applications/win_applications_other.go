//go:build !windows

package win_applications

import (
	"context"
)

// WinApplications represents the Windows application artifacts collection module (no-op on non-Windows).
type WinApplications struct{}

// NewWinApplications creates a new Windows application artifacts collection module.
func NewWinApplications() *WinApplications {
	return &WinApplications{}
}

// Name returns the module's identifier.
func (w *WinApplications) Name() string {
	return "windows/applications"
}

// Collect is a no-op on non-Windows systems.
func (w *WinApplications) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}