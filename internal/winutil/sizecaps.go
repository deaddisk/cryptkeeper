// Package winutil provides size limiting and tail copy utilities for cryptkeeper.
package winutil

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

const (
	// DefaultMaxFileSizeMB is the default maximum size for individual files
	DefaultMaxFileSizeMB = 512

	// DefaultMaxTotalMB is the default maximum total size for all files in a module
	DefaultMaxTotalMB = 2048

	// BufferSize for streaming operations
	BufferSize = 64 * 1024 // 64KB buffer
)

// SizeConstraints defines limits for file collection
type SizeConstraints struct {
	MaxFileSizeMB  int64 // Maximum size for a single file in MB
	MaxTotalMB     int64 // Maximum total size for all files in MB
	CurrentTotalMB int64 // Current total size collected
}

// NewSizeConstraints creates size constraints with default values
func NewSizeConstraints() *SizeConstraints {
	return &SizeConstraints{
		MaxFileSizeMB:  DefaultMaxFileSizeMB,
		MaxTotalMB:     DefaultMaxTotalMB,
		CurrentTotalMB: 0,
	}
}

// CanCollectFile checks if a file can be collected based on size constraints
func (sc *SizeConstraints) CanCollectFile(fileSizeBytes int64) bool {
	fileSizeMB := fileSizeBytes / (1024 * 1024)
	
	// Check if file exceeds individual file limit
	if fileSizeMB > sc.MaxFileSizeMB {
		return false
	}
	
	// Check if adding this file would exceed total limit
	if sc.CurrentTotalMB+fileSizeMB > sc.MaxTotalMB {
		return false
	}
	
	return true
}

// AddFileSize updates the current total size
func (sc *SizeConstraints) AddFileSize(fileSizeBytes int64) {
	sc.CurrentTotalMB += fileSizeBytes / (1024 * 1024)
}

// TailCopy copies the tail (end) of a large file when it exceeds size limits.
// This is useful for log files where recent entries are most important.
// Returns bytes copied, SHA-256 hash, and whether the file was truncated.
func TailCopy(srcPath, dstPath string, maxBytes int64) (bytes int64, sha256Hex string, truncated bool, err error) {
	// Open source file
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return 0, "", false, fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Get file size
	stat, err := srcFile.Stat()
	if err != nil {
		return 0, "", false, fmt.Errorf("failed to stat source file: %w", err)
	}

	fileSize := stat.Size()
	
	// If file is within limits, do a normal copy
	if fileSize <= maxBytes {
		return FullCopy(srcPath, dstPath)
	}

	// File exceeds limits, copy tail
	truncated = true
	
	// Seek to the position where we want to start copying (tail)
	seekPos := fileSize - maxBytes
	if _, err := srcFile.Seek(seekPos, io.SeekStart); err != nil {
		return 0, "", false, fmt.Errorf("failed to seek to tail position: %w", err)
	}

	// Create destination file
	dstFile, err := os.Create(dstPath)
	if err != nil {
		return 0, "", false, fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	// Create hasher
	hasher := sha256.New()
	
	// Create multi-writer for destination and hash
	multiWriter := io.MultiWriter(dstFile, hasher)
	
	// Copy limited bytes from tail
	bytes, err = io.CopyN(multiWriter, srcFile, maxBytes)
	if err != nil && err != io.EOF {
		return 0, "", true, fmt.Errorf("failed to copy file tail: %w", err)
	}

	sha256Hex = fmt.Sprintf("%x", hasher.Sum(nil))
	return bytes, sha256Hex, true, nil
}

// FullCopy performs a complete file copy with hashing
func FullCopy(srcPath, dstPath string) (bytes int64, sha256Hex string, truncated bool, err error) {
	srcFile, err := os.Open(srcPath)
	if err != nil {
		return 0, "", false, fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dstPath)
	if err != nil {
		return 0, "", false, fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dstFile.Close()

	hasher := sha256.New()
	multiWriter := io.MultiWriter(dstFile, hasher)
	
	bytes, err = io.Copy(multiWriter, srcFile)
	if err != nil {
		return 0, "", false, fmt.Errorf("failed to copy file: %w", err)
	}

	sha256Hex = fmt.Sprintf("%x", hasher.Sum(nil))
	return bytes, sha256Hex, false, nil
}

// SmartCopy decides whether to do a full copy or tail copy based on size constraints
func SmartCopy(srcPath, dstPath string, constraints *SizeConstraints) (bytes int64, sha256Hex string, truncated bool, err error) {
	// Get source file size
	stat, err := os.Stat(srcPath)
	if err != nil {
		return 0, "", false, fmt.Errorf("failed to stat source file: %w", err)
	}

	fileSize := stat.Size()
	maxBytes := constraints.MaxFileSizeMB * 1024 * 1024

	// Check if we can collect this file
	if !constraints.CanCollectFile(fileSize) {
		// File is too large, try tail copy with max allowed size
		maxAllowedBytes := (constraints.MaxTotalMB - constraints.CurrentTotalMB) * 1024 * 1024
		if maxAllowedBytes <= 0 {
			return 0, "", false, fmt.Errorf("total size limit exceeded, cannot collect file")
		}
		
		if maxAllowedBytes > maxBytes {
			maxAllowedBytes = maxBytes
		}
		
		bytes, sha256Hex, truncated, err = TailCopy(srcPath, dstPath, maxAllowedBytes)
	} else {
		// File is within limits, do full copy
		bytes, sha256Hex, truncated, err = FullCopy(srcPath, dstPath)
	}

	// Update size constraints if successful
	if err == nil {
		constraints.AddFileSize(bytes)
	}

	return bytes, sha256Hex, truncated, err
}