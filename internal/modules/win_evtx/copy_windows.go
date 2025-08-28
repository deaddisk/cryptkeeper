//go:build windows

package win_evtx

import (
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// copyFileWithTolerantSharing copies a file using Windows APIs with generous sharing flags
// to tolerate locks that may exist on event log files.
func copyFileWithTolerantSharing(srcPath, destPath string) error {
	// Convert paths to UTF-16 for Windows APIs
	srcPtr, err := syscall.UTF16PtrFromString(srcPath)
	if err != nil {
		return fmt.Errorf("failed to convert source path to UTF-16: %w", err)
	}

	// Open source file with generous sharing flags
	srcHandle, err := windows.CreateFile(
		srcPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, // Generous sharing
		nil, // Security attributes
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_BACKUP_SEMANTICS, // Backup semantics for better compatibility
		0, // Template file
	)
	if err != nil {
		return fmt.Errorf("failed to open source file %s: %w", srcPath, err)
	}
	defer windows.CloseHandle(srcHandle)

	// Convert Windows handle to Go file for easy I/O operations
	srcFile := os.NewFile(uintptr(srcHandle), srcPath)
	defer srcFile.Close()

	// Create destination file
	destFile, err := os.Create(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file %s: %w", destPath, err)
	}
	defer destFile.Close()

	// Stream copy from source to destination
	_, err = io.Copy(destFile, srcFile)
	if err != nil {
		return fmt.Errorf("failed to copy file contents from %s to %s: %w", srcPath, destPath, err)
	}

	return nil
}

// getLogFilePath constructs the path to a raw event log file in the Windows logs directory.
func getLogFilePath(logFileName string) string {
	// Get the Windows directory (usually C:\Windows)
	winDir := os.Getenv("SystemRoot")
	if winDir == "" {
		winDir = "C:\\Windows" // Fallback
	}
	
	return fmt.Sprintf("%s\\System32\\winevt\\Logs\\%s", winDir, logFileName)
}

// channelToLogFile maps channel names to their corresponding log file names.
var channelToLogFile = map[string]string{
	"Security":                                    "Security.evtx",
	"System":                                      "System.evtx",
	"Microsoft-Windows-PowerShell/Operational":   "Microsoft-Windows-PowerShell%4Operational.evtx",
}

// getChannelLogFilePath returns the full path to the raw log file for a given channel.
func getChannelLogFilePath(channel string) (string, bool) {
	logFile, exists := channelToLogFile[channel]
	if !exists {
		return "", false
	}
	return getLogFilePath(logFile), true
}