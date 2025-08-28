//go:build !windows

package win_evtx

import (
	"context"
)

// WinEvtx represents the Windows Event Log collection module stub for non-Windows platforms.
type WinEvtx struct{}

// NewWinEvtx creates a new Windows Event Log collection module stub.
func NewWinEvtx() *WinEvtx {
	return &WinEvtx{}
}

// SetSinceTime is a no-op on non-Windows platforms.
func (w *WinEvtx) SetSinceTime(sinceRFC3339 string) {
	// No-op on non-Windows platforms
}

// Name returns the module's identifier.
func (w *WinEvtx) Name() string {
	return "windows/evtx"
}

// Collect is a no-op on non-Windows platforms and always returns nil.
func (w *WinEvtx) Collect(ctx context.Context, outDir string) error {
	// This module only works on Windows, so it's a no-op on other platforms
	return nil
}