// Package win_systemconfig provides Windows system configuration collection for cryptkeeper.
package win_systemconfig

import (
	"encoding/json"
	"os"
	"time"
)

// SystemConfigItem represents a collected system configuration file.
type SystemConfigItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "services", "startup", "environment", "timezone", "hosts"
}

// SystemConfigError represents an error that occurred during collection.
type SystemConfigError struct {
	Target string `json:"target"` // What failed (e.g., specific command)
	Error  string `json:"error"`  // Error message
}

// SystemConfigManifest represents the complete manifest for system configuration collection.
type SystemConfigManifest struct {
	CreatedUTC         string               `json:"created_utc"`
	Host               string               `json:"host"`
	CryptkeeperVersion string               `json:"cryptkeeper_version"`
	Items              []SystemConfigItem  `json:"items"`
	Errors             []SystemConfigError `json:"errors"`
	TotalFiles         int                  `json:"total_files"`
	CollectedFiles     int                  `json:"collected_files"`
}

// NewSystemConfigManifest creates a new system configuration manifest with basic information.
func NewSystemConfigManifest(hostname string) *SystemConfigManifest {
	return &SystemConfigManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]SystemConfigItem, 0),
		Errors:             make([]SystemConfigError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected system configuration item to the manifest.
func (sm *SystemConfigManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	sm.Items = append(sm.Items, SystemConfigItem{
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
func (sm *SystemConfigManifest) AddError(target, errorMsg string) {
	sm.Errors = append(sm.Errors, SystemConfigError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (sm *SystemConfigManifest) IncrementTotalFiles() {
	sm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (sm *SystemConfigManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(sm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}