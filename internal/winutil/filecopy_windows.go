//go:build windows

package winutil

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

// OpenForCopy opens a file for reading using Windows APIs with generous sharing flags
// to handle locked system files. Uses backup semantics when available.
func OpenForCopy(path string) (*os.File, error) {
	// Convert path to UTF-16 for Windows APIs
	pathPtr, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("failed to convert path to UTF-16: %w", err)
	}

	// Open with generous sharing flags and backup semantics
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, // Generous sharing
		nil, // Security attributes
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_BACKUP_SEMANTICS, // Backup semantics
		0, // Template file
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}

	// Convert Windows handle to Go file
	file := os.NewFile(uintptr(handle), path)
	return file, nil
}

// CopyFileStreaming performs a streaming copy from an open source file to a destination path,
// computing SHA-256 hash during the copy. Returns bytes copied and hex-encoded hash.
func CopyFileStreaming(src *os.File, dstPath string) (bytes int64, sha256Hex string, err error) {
	// Create destination file
	dst, err := os.Create(dstPath)
	if err != nil {
		return 0, "", fmt.Errorf("failed to create destination file %s: %w", dstPath, err)
	}
	defer dst.Close()

	// Create SHA-256 hasher
	hasher := sha256.New()

	// Create a multi-writer to write to both destination and hasher
	multiWriter := io.MultiWriter(dst, hasher)

	// Stream copy from source through multi-writer
	bytes, err = io.Copy(multiWriter, src)
	if err != nil {
		return 0, "", fmt.Errorf("failed to copy file contents: %w", err)
	}

	// Get the hex-encoded hash
	sha256Hex = fmt.Sprintf("%x", hasher.Sum(nil))

	return bytes, sha256Hex, nil
}

// CopyFile is a convenience function that opens a source file and performs streaming copy
// with hash computation. Returns file size, hash, and any error.
func CopyFile(srcPath, dstPath string) (size int64, sha256Hex string, err error) {
	// Open source file with tolerant sharing
	srcFile, err := OpenForCopy(srcPath)
	if err != nil {
		return 0, "", fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Perform streaming copy with hashing
	size, sha256Hex, err = CopyFileStreaming(srcFile, dstPath)
	if err != nil {
		return 0, "", fmt.Errorf("failed to copy file: %w", err)
	}

	return size, sha256Hex, nil
}

// EnsureDir creates a directory and all necessary parent directories.
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}

// SafeRel safely computes a relative path, guarding against directory traversal attacks.
// This is important when creating archive paths to prevent tar slip vulnerabilities.
func SafeRel(base, path string) (string, error) {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return "", err
	}

	// Check for directory traversal attempts
	if strings.Contains(rel, "..") {
		return "", fmt.Errorf("path contains directory traversal: %s", rel)
	}

	return rel, nil
}