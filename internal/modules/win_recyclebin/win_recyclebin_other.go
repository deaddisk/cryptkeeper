//go:build !windows

package win_recyclebin

import ("context")

type WinRecycleBin struct{}
func NewWinRecycleBin() *WinRecycleBin { return &WinRecycleBin{} }
func (w *WinRecycleBin) Name() string { return "windows/recyclebin" }
func (w *WinRecycleBin) Collect(ctx context.Context, outDir string) error { return nil }