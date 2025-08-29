//go:build !windows

package win_usb

import ("context")

type WinUSB struct{}

func NewWinUSB() *WinUSB { return &WinUSB{} }
func (w *WinUSB) Name() string { return "windows/usb" }
func (w *WinUSB) Collect(ctx context.Context, outDir string) error { return nil }