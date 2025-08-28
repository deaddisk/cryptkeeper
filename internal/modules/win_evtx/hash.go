// Package win_evtx provides Windows Event Log collection for cryptkeeper.
package win_evtx

import (
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// ComputeFileSHA256 calculates the SHA-256 hash of a file using streaming I/O.
// Returns the hex-encoded hash string and the file size in bytes.
func ComputeFileSHA256(filePath string) (hash string, size int64, err error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", 0, fmt.Errorf("failed to open file for hashing: %w", err)
	}
	defer file.Close()

	// Get file size
	stat, err := file.Stat()
	if err != nil {
		return "", 0, fmt.Errorf("failed to stat file for size: %w", err)
	}
	size = stat.Size()

	// Create SHA-256 hasher
	hasher := sha256.New()

	// Stream the file through the hasher
	if _, err := io.Copy(hasher, file); err != nil {
		return "", 0, fmt.Errorf("failed to hash file contents: %w", err)
	}

	// Get the hex-encoded hash
	hash = fmt.Sprintf("%x", hasher.Sum(nil))

	return hash, size, nil
}