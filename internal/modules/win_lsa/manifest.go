// Package win_lsa provides LSA Secrets and authentication data collection for cryptkeeper.
package win_lsa

import (
	"encoding/json"
	"os"
	"time"
)

// LSAItem represents a collected LSA-related file.
type LSAItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "lsa_policy", "auth_packages", "domain_info"
}

// LSAError represents an error that occurred during collection.
type LSAError struct {
	Target string `json:"target"` // What failed (e.g., specific command)
	Error  string `json:"error"`  // Error message
}

// LSAManifest represents the complete manifest for LSA collection.
type LSAManifest struct {
	CreatedUTC         string     `json:"created_utc"`
	Host               string     `json:"host"`
	CryptkeeperVersion string     `json:"cryptkeeper_version"`
	Items              []LSAItem  `json:"items"`
	Errors             []LSAError `json:"errors"`
	TotalFiles         int        `json:"total_files"`
	CollectedFiles     int        `json:"collected_files"`
}

// NewLSAManifest creates a new LSA manifest with basic information.
func NewLSAManifest(hostname string) *LSAManifest {
	return &LSAManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]LSAItem, 0),
		Errors:             make([]LSAError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected LSA item to the manifest.
func (lm *LSAManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	lm.Items = append(lm.Items, LSAItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	lm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (lm *LSAManifest) AddError(target, errorMsg string) {
	lm.Errors = append(lm.Errors, LSAError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (lm *LSAManifest) IncrementTotalFiles() {
	lm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (lm *LSAManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(lm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}