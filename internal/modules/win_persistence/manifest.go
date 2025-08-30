// Package win_persistence provides Windows persistence and malware hunting artifacts collection for cryptkeeper.
package win_persistence

import (
	"encoding/json"
	"os"
	"time"
)

// PersistenceItem represents a collected persistence/malware hunting artifact file.
type PersistenceItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "autoruns", "shellbags", "thumbnails", "iconcache", "com_objects"
}

// PersistenceError represents an error that occurred during collection.
type PersistenceError struct {
	Target string `json:"target"` // What failed (e.g., specific artifact type)
	Error  string `json:"error"`  // Error message
}

// PersistenceManifest represents the complete manifest for persistence artifacts collection.
type PersistenceManifest struct {
	CreatedUTC         string              `json:"created_utc"`
	Host               string              `json:"host"`
	CryptkeeperVersion string              `json:"cryptkeeper_version"`
	Items              []PersistenceItem   `json:"items"`
	Errors             []PersistenceError  `json:"errors"`
	TotalFiles         int                 `json:"total_files"`
	CollectedFiles     int                 `json:"collected_files"`
}

// NewPersistenceManifest creates a new persistence artifacts manifest with basic information.
func NewPersistenceManifest(hostname string) *PersistenceManifest {
	return &PersistenceManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]PersistenceItem, 0),
		Errors:             make([]PersistenceError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected persistence item to the manifest.
func (pm *PersistenceManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	pm.Items = append(pm.Items, PersistenceItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	pm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (pm *PersistenceManifest) AddError(target, errorMsg string) {
	pm.Errors = append(pm.Errors, PersistenceError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (pm *PersistenceManifest) IncrementTotalFiles() {
	pm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (pm *PersistenceManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(pm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}