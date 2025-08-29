//go:build !windows

package win_browser

import ("context")

type WinBrowser struct{}
func NewWinBrowser() *WinBrowser { return &WinBrowser{} }
func (w *WinBrowser) Name() string { return "windows/browser" }
func (w *WinBrowser) Collect(ctx context.Context, outDir string) error { return nil }