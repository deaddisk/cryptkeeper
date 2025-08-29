//go:build !windows

package win_firewall_net

import (
	"context"
)

// WinFirewallNet represents the Windows firewall/network collection module (no-op on non-Windows).
type WinFirewallNet struct{}

// NewWinFirewallNet creates a new Windows firewall/network collection module.
func NewWinFirewallNet() *WinFirewallNet {
	return &WinFirewallNet{}
}

// Name returns the module's identifier.
func (w *WinFirewallNet) Name() string {
	return "windows/firewall_net"
}

// Collect is a no-op on non-Windows systems.
func (w *WinFirewallNet) Collect(ctx context.Context, outDir string) error {
	// No-op on non-Windows systems
	return nil
}