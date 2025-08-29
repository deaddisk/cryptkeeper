//go:build windows

package win_usb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"cryptkeeper/internal/winutil"
)

type WinUSB struct{}

func NewWinUSB() *WinUSB {
	return &WinUSB{}
}

func (w *WinUSB) Name() string {
	return "windows/usb"
}

func (w *WinUSB) Collect(ctx context.Context, outDir string) error {
	usbDir := filepath.Join(outDir, "windows", "usb")
	if err := winutil.EnsureDir(usbDir); err != nil {
		return fmt.Errorf("failed to create usb directory: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	manifest := NewUSBManifest(hostname)
	constraints := winutil.NewSizeConstraints()

	// Collect setupapi.dev.log
	if err := w.collectSetupAPILog(ctx, usbDir, manifest, constraints); err != nil {
		manifest.AddError("setupapi_log", fmt.Sprintf("Failed to collect setupapi log: %v", err))
	}

	// Note: USB registry keys are covered by SYSTEM hive in win_registry module
	manifest.AddItem("README_USB_Registry.txt", 0, "", false, 
		*new(time.Time), "registry_note", 
		"USB registry keys (USBSTOR, MountedDevices) are captured in the SYSTEM hive by win_registry module")

	manifestPath := filepath.Join(usbDir, "manifest.json")
	if err := manifest.WriteManifest(manifestPath); err != nil {
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	return nil
}

func (w *WinUSB) collectSetupAPILog(ctx context.Context, outDir string, manifest *USBManifest, constraints *winutil.SizeConstraints) error {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemDrive := os.Getenv("SystemDrive")
		if systemDrive == "" {
			systemDrive = "C:"
		}
		systemRoot = filepath.Join(systemDrive, "Windows")
	}

	setupAPIPath := filepath.Join(systemRoot, "inf", "setupapi.dev.log")
	
	stat, err := os.Stat(setupAPIPath)
	if err != nil {
		return fmt.Errorf("setupapi.dev.log not found: %w", err)
	}

	manifest.IncrementTotalFiles()

	destPath := filepath.Join(outDir, "setupapi.dev.log")
	size, sha256Hex, truncated, err := winutil.SmartCopy(setupAPIPath, destPath, constraints)
	if err != nil {
		return fmt.Errorf("failed to copy setupapi.dev.log: %w", err)
	}

	manifest.AddItem("setupapi.dev.log", size, sha256Hex, truncated, stat.ModTime(), "device_log", "Windows device installation log")
	return nil
}