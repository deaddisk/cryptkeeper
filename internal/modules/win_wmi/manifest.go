// Package win_wmi provides Windows WMI repository collection for cryptkeeper.
package win_wmi

import (
	"encoding/json"
	"os"
	"time"
)

// WMIItem represents a collected WMI repository file.
type WMIItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "repository", "subscription_info"
}

// WMIError represents an error that occurred during collection.
type WMIError struct {
	Target string `json:"target"` // What failed (e.g., specific file path)
	Error  string `json:"error"`  // Error message
}

// WMIManifest represents the complete manifest for WMI collection.
type WMIManifest struct {
	CreatedUTC         string    `json:"created_utc"`
	Host               string    `json:"host"`
	CryptkeeperVersion string    `json:"cryptkeeper_version"`
	Items              []WMIItem `json:"items"`
	Errors             []WMIError `json:"errors"`
	TotalFiles         int       `json:"total_files"`
	CollectedFiles     int       `json:"collected_files"`
}

// NewWMIManifest creates a new WMI manifest with basic information.
func NewWMIManifest(hostname string) *WMIManifest {
	return &WMIManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]WMIItem, 0),
		Errors:             make([]WMIError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected WMI item to the manifest.
func (wm *WMIManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	wm.Items = append(wm.Items, WMIItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	wm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (wm *WMIManifest) AddError(target, errorMsg string) {
	wm.Errors = append(wm.Errors, WMIError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (wm *WMIManifest) IncrementTotalFiles() {
	wm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (wm *WMIManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(wm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}