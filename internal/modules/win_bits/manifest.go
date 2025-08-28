// Package win_bits provides Windows Background Intelligent Transfer Service collection for cryptkeeper.
package win_bits

import (
	"encoding/json"
	"os"
	"time"
)

// BITSItem represents a collected BITS job queue file.
type BITSItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "queue", "job"
}

// BITSError represents an error that occurred during collection.
type BITSError struct {
	Target string `json:"target"` // What failed (e.g., specific file path)
	Error  string `json:"error"`  // Error message
}

// BITSManifest represents the complete manifest for BITS collection.
type BITSManifest struct {
	CreatedUTC         string      `json:"created_utc"`
	Host               string      `json:"host"`
	CryptkeeperVersion string      `json:"cryptkeeper_version"`
	Items              []BITSItem  `json:"items"`
	Errors             []BITSError `json:"errors"`
	TotalFiles         int         `json:"total_files"`
	CollectedFiles     int         `json:"collected_files"`
}

// NewBITSManifest creates a new BITS manifest with basic information.
func NewBITSManifest(hostname string) *BITSManifest {
	return &BITSManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]BITSItem, 0),
		Errors:             make([]BITSError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected BITS item to the manifest.
func (bm *BITSManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	bm.Items = append(bm.Items, BITSItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	bm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (bm *BITSManifest) AddError(target, errorMsg string) {
	bm.Errors = append(bm.Errors, BITSError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (bm *BITSManifest) IncrementTotalFiles() {
	bm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (bm *BITSManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(bm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}