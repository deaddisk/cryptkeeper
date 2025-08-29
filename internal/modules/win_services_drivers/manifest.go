// Package win_services_drivers provides Windows services and drivers collection for cryptkeeper.
package win_services_drivers

import (
	"encoding/json"
	"os"
	"time"
)

// ServiceDriverItem represents a collected service or driver file.
type ServiceDriverItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "driver", "system_info"
}

// ServiceDriverError represents an error that occurred during collection.
type ServiceDriverError struct {
	Target string `json:"target"` // What failed (e.g., specific file path)
	Error  string `json:"error"`  // Error message
}

// ServiceDriverManifest represents the complete manifest for services/drivers collection.
type ServiceDriverManifest struct {
	CreatedUTC         string                `json:"created_utc"`
	Host               string                `json:"host"`
	CryptkeeperVersion string                `json:"cryptkeeper_version"`
	Items              []ServiceDriverItem   `json:"items"`
	Errors             []ServiceDriverError  `json:"errors"`
	TotalFiles         int                   `json:"total_files"`
	CollectedFiles     int                   `json:"collected_files"`
}

// NewServiceDriverManifest creates a new services/drivers manifest with basic information.
func NewServiceDriverManifest(hostname string) *ServiceDriverManifest {
	return &ServiceDriverManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]ServiceDriverItem, 0),
		Errors:             make([]ServiceDriverError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected service/driver item to the manifest.
func (sm *ServiceDriverManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	sm.Items = append(sm.Items, ServiceDriverItem{
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
func (sm *ServiceDriverManifest) AddError(target, errorMsg string) {
	sm.Errors = append(sm.Errors, ServiceDriverError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (sm *ServiceDriverManifest) IncrementTotalFiles() {
	sm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (sm *ServiceDriverManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(sm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}