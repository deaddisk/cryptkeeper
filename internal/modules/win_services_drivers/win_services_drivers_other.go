//go:build !windows

package win_services_drivers

import (
	"context"
)

// WinServicesDrivers represents the Windows services/drivers collection module (no-op on non-Windows).
type WinServicesDrivers struct{}

// NewWinServicesDrivers creates a new Windows services/drivers collection module.
func NewWinServicesDrivers() *WinServicesDrivers {
	return &WinServicesDrivers{}
}

// Name returns the module's identifier.
func (w *WinServicesDrivers) Name() string {
	return "windows/services_drivers"
}

// Collect is a no-op on non-Windows systems.
func (w *WinServicesDrivers) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}