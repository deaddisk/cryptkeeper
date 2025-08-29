// Package win_rdp provides Windows RDP artifacts collection for cryptkeeper.
package win_rdp

import (
	"encoding/json"
	"os"
	"time"
)

// RDPItem represents a collected RDP artifact file.
type RDPItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "bitmap_cache", "config"
}

// RDPError represents an error that occurred during collection.
type RDPError struct {
	Target string `json:"target"` // What failed (e.g., specific file path)
	Error  string `json:"error"`  // Error message
}

// RDPManifest represents the complete manifest for RDP collection.
type RDPManifest struct {
	CreatedUTC         string    `json:"created_utc"`
	Host               string    `json:"host"`
	CryptkeeperVersion string    `json:"cryptkeeper_version"`
	Items              []RDPItem `json:"items"`
	Errors             []RDPError `json:"errors"`
	TotalFiles         int       `json:"total_files"`
	CollectedFiles     int       `json:"collected_files"`
}

// NewRDPManifest creates a new RDP manifest with basic information.
func NewRDPManifest(hostname string) *RDPManifest {
	return &RDPManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]RDPItem, 0),
		Errors:             make([]RDPError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected RDP item to the manifest.
func (rm *RDPManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	rm.Items = append(rm.Items, RDPItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	rm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (rm *RDPManifest) AddError(target, errorMsg string) {
	rm.Errors = append(rm.Errors, RDPError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (rm *RDPManifest) IncrementTotalFiles() {
	rm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (rm *RDPManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(rm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}