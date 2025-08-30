// Package win_modern provides Windows modern/cloud artifacts collection for cryptkeeper.
package win_modern

import (
	"encoding/json"
	"os"
	"time"
)

// ModernItem represents a collected modern Windows artifact file.
type ModernItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "onedrive", "store_apps", "cortana", "timeline", "clipboard"
}

// ModernError represents an error that occurred during collection.
type ModernError struct {
	Target string `json:"target"` // What failed (e.g., specific artifact type)
	Error  string `json:"error"`  // Error message
}

// ModernManifest represents the complete manifest for modern Windows artifacts collection.
type ModernManifest struct {
	CreatedUTC         string        `json:"created_utc"`
	Host               string        `json:"host"`
	CryptkeeperVersion string        `json:"cryptkeeper_version"`
	Items              []ModernItem  `json:"items"`
	Errors             []ModernError `json:"errors"`
	TotalFiles         int           `json:"total_files"`
	CollectedFiles     int           `json:"collected_files"`
}

// NewModernManifest creates a new modern artifacts manifest with basic information.
func NewModernManifest(hostname string) *ModernManifest {
	return &ModernManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]ModernItem, 0),
		Errors:             make([]ModernError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected modern item to the manifest.
func (mm *ModernManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	mm.Items = append(mm.Items, ModernItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	mm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (mm *ModernManifest) AddError(target, errorMsg string) {
	mm.Errors = append(mm.Errors, ModernError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (mm *ModernManifest) IncrementTotalFiles() {
	mm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (mm *ModernManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(mm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}