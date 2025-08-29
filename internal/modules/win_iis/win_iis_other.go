//go:build !windows

package win_iis

import ("context")

type WinIIS struct{}
func NewWinIIS() *WinIIS { return &WinIIS{} }
func (w *WinIIS) Name() string { return "windows/iis" }
func (w *WinIIS) Collect(ctx context.Context, outDir string) error { return nil }