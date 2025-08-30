// Package win_applications provides Windows application-specific artifacts collection for cryptkeeper.
package win_applications

import (
	"encoding/json"
	"os"
	"time"
)

// ApplicationItem represents a collected application artifact file.
type ApplicationItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "office", "skype", "teams", "outlook", "antivirus"
}

// ApplicationError represents an error that occurred during collection.
type ApplicationError struct {
	Target string `json:"target"` // What failed (e.g., specific application)
	Error  string `json:"error"`  // Error message
}

// ApplicationManifest represents the complete manifest for application artifacts collection.
type ApplicationManifest struct {
	CreatedUTC         string              `json:"created_utc"`
	Host               string              `json:"host"`
	CryptkeeperVersion string              `json:"cryptkeeper_version"`
	Items              []ApplicationItem   `json:"items"`
	Errors             []ApplicationError  `json:"errors"`
	TotalFiles         int                 `json:"total_files"`
	CollectedFiles     int                 `json:"collected_files"`
}

// NewApplicationManifest creates a new application artifacts manifest with basic information.
func NewApplicationManifest(hostname string) *ApplicationManifest {
	return &ApplicationManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]ApplicationItem, 0),
		Errors:             make([]ApplicationError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected application item to the manifest.
func (am *ApplicationManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	am.Items = append(am.Items, ApplicationItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	am.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (am *ApplicationManifest) AddError(target, errorMsg string) {
	am.Errors = append(am.Errors, ApplicationError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (am *ApplicationManifest) IncrementTotalFiles() {
	am.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (am *ApplicationManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(am, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}