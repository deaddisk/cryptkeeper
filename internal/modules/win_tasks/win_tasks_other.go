//go:build !windows

package win_tasks

import (
	"context"
)

// WinTasks represents the Windows scheduled tasks collection module (no-op on non-Windows).
type WinTasks struct{}

// NewWinTasks creates a new Windows scheduled tasks collection module.
func NewWinTasks() *WinTasks {
	return &WinTasks{}
}

// Name returns the module's identifier.
func (w *WinTasks) Name() string {
	return "windows/tasks"
}

// Collect is a no-op on non-Windows systems.
func (w *WinTasks) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}