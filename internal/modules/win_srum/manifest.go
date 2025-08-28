// Package win_srum provides Windows System Resource Usage Monitor collection for cryptkeeper.
package win_srum

import (
	"encoding/json"
	"os"
	"time"
)

// SRUMItem represents a collected SRUM database file.
type SRUMItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "database", "log"
}

// SRUMError represents an error that occurred during collection.
type SRUMError struct {
	Target string `json:"target"` // What failed (e.g., specific file path)
	Error  string `json:"error"`  // Error message
}

// SRUMManifest represents the complete manifest for SRUM collection.
type SRUMManifest struct {
	CreatedUTC         string      `json:"created_utc"`
	Host               string      `json:"host"`
	CryptkeeperVersion string      `json:"cryptkeeper_version"`
	Items              []SRUMItem  `json:"items"`
	Errors             []SRUMError `json:"errors"`
	TotalFiles         int         `json:"total_files"`
	CollectedFiles     int         `json:"collected_files"`
}

// NewSRUMManifest creates a new SRUM manifest with basic information.
func NewSRUMManifest(hostname string) *SRUMManifest {
	return &SRUMManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]SRUMItem, 0),
		Errors:             make([]SRUMError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected SRUM item to the manifest.
func (sm *SRUMManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	sm.Items = append(sm.Items, SRUMItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	sm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (sm *SRUMManifest) AddError(target, errorMsg string) {
	sm.Errors = append(sm.Errors, SRUMError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (sm *SRUMManifest) IncrementTotalFiles() {
	sm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (sm *SRUMManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(sm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}