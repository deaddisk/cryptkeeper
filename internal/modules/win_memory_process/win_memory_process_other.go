//go:build !windows

package win_memory_process

import (
	"context"
)

// WinMemoryProcess represents the Windows memory/process collection module (no-op on non-Windows).
type WinMemoryProcess struct{}

// NewWinMemoryProcess creates a new Windows memory/process collection module.
func NewWinMemoryProcess() *WinMemoryProcess {
	return &WinMemoryProcess{}
}

// Name returns the module's identifier.
func (w *WinMemoryProcess) Name() string {
	return "windows/memory_process"
}

// Collect is a no-op on non-Windows systems.
func (w *WinMemoryProcess) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}