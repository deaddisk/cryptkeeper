// Package core provides bundling and encryption functionality for cryptkeeper artifacts.
package core

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"
)

// PackageMetadata contains information about the created package.
type PackageMetadata struct {
	Path         string `json:"archive_path"`
	Encrypted    bool   `json:"encrypted"`
	FileCount    int    `json:"file_count"`
	BytesWritten int64  `json:"bytes_written"`
}

// BundleAndMaybeEncrypt creates a tar.gz archive of the artifacts directory,
// optionally encrypting it with the provided age public key.
func BundleAndMaybeEncrypt(ctx context.Context, artifactsDir, outDir, hostname string, timestamp time.Time, agePublicKey string) (*PackageMetadata, error) {
	// Generate output filename
	timeStr := timestamp.UTC().Format("20060102T150405Z")
	baseFilename := fmt.Sprintf("cryptkeeper_%s_%s.tar.gz", hostname, timeStr)
	
	var outputPath string
	var encrypted bool
	
	if agePublicKey != "" {
		outputPath = filepath.Join(outDir, baseFilename+".age")
		encrypted = true
	} else {
		outputPath = filepath.Join(outDir, baseFilename)
		encrypted = false
	}

	// Create output file
	outFile, err := os.Create(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create output file %s: %w", outputPath, err)
	}
	defer outFile.Close()

	// Set up the writer pipeline
	var gzWriter *gzip.Writer
	var tarWriter *tar.Writer
	var encWriter io.WriteCloser
	var bytesWritten int64

	if encrypted {
		// Parse the age recipient
		recipient, err := age.ParseX25519Recipient(agePublicKey)
		if err != nil {
			return nil, fmt.Errorf("failed to parse age public key: %w", err)
		}

		// Create encrypted writer
		encWriter, err = age.Encrypt(outFile, recipient)
		if err != nil {
			return nil, fmt.Errorf("failed to create age encryption writer: %w", err)
		}

		// Create gzip writer on top of encrypted writer
		gzWriter = gzip.NewWriter(encWriter)
	} else {
		// Create gzip writer directly on file
		gzWriter = gzip.NewWriter(outFile)
	}

	// Create tar writer on top of gzip writer
	tarWriter = tar.NewWriter(gzWriter)

	// Track statistics
	fileCount := 0
	bytesCounter := &countingWriter{wrapped: tarWriter}
	
	// Walk the artifacts directory and add files to the archive
	err = filepath.WalkDir(artifactsDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Check for context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip the root directory itself
		if path == artifactsDir {
			return nil
		}

		// Calculate relative path for the tar archive
		relPath, err := filepath.Rel(artifactsDir, path)
		if err != nil {
			return fmt.Errorf("failed to calculate relative path for %s: %w", path, err)
		}

		// Convert to forward slashes for tar format and prefix with "artifacts/"
		tarPath := "artifacts/" + filepath.ToSlash(relPath)

		if d.IsDir() {
			// Add directory entry
			header := &tar.Header{
				Name:     tarPath + "/",
				Mode:     0755,
				Typeflag: tar.TypeDir,
				ModTime:  timestamp,
			}
			return tarWriter.WriteHeader(header)
		}

		// Handle regular files
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open file %s: %w", path, err)
		}
		defer file.Close()

		// Get file info
		info, err := file.Stat()
		if err != nil {
			return fmt.Errorf("failed to stat file %s: %w", path, err)
		}

		// Create tar header
		header := &tar.Header{
			Name:    tarPath,
			Mode:    0644,
			Size:    info.Size(),
			ModTime: info.ModTime(),
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			return fmt.Errorf("failed to write tar header for %s: %w", path, err)
		}

		// Copy file contents using streaming I/O
		if _, err := io.Copy(bytesCounter, file); err != nil {
			return fmt.Errorf("failed to copy file %s to archive: %w", path, err)
		}

		fileCount++
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk artifacts directory: %w", err)
	}

	// Close writers in correct order
	if err := tarWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close tar writer: %w", err)
	}

	if err := gzWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close gzip writer: %w", err)
	}

	if encrypted {
		if err := encWriter.Close(); err != nil {
			return nil, fmt.Errorf("failed to close age encryption writer: %w", err)
		}
	}

	// Get the final file size
	if stat, err := outFile.Stat(); err == nil {
		bytesWritten = stat.Size()
	} else {
		bytesWritten = bytesCounter.count
	}

	return &PackageMetadata{
		Path:         outputPath,
		Encrypted:    encrypted,
		FileCount:    fileCount,
		BytesWritten: bytesWritten,
	}, nil
}

// countingWriter wraps another writer and counts bytes written.
type countingWriter struct {
	wrapped io.Writer
	count   int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.wrapped.Write(p)
	c.count += int64(n)
	return n, err
}

// ValidateAgePublicKey validates that a string is a valid age public key.
func ValidateAgePublicKey(key string) error {
	if !strings.HasPrefix(key, "age1") {
		return fmt.Errorf("age public key must start with 'age1'")
	}
	
	_, err := age.ParseX25519Recipient(key)
	if err != nil {
		return fmt.Errorf("invalid age public key: %w", err)
	}
	
	return nil
}