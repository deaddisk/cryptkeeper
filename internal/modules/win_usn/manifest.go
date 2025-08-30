// Package win_usn provides NTFS USN Journal collection for cryptkeeper.
package win_usn

import (
	"encoding/json"
	"os"
	"time"
)

// USNItem represents a collected USN Journal-related file.
type USNItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "usn_info", "journal_metadata", "change_records"
}

// USNError represents an error that occurred during collection.
type USNError struct {
	Target string `json:"target"` // What failed (e.g., specific volume)
	Error  string `json:"error"`  // Error message
}

// USNManifest represents the complete manifest for USN Journal collection.
type USNManifest struct {
	CreatedUTC         string     `json:"created_utc"`
	Host               string     `json:"host"`
	CryptkeeperVersion string     `json:"cryptkeeper_version"`
	Items              []USNItem  `json:"items"`
	Errors             []USNError `json:"errors"`
	TotalFiles         int        `json:"total_files"`
	CollectedFiles     int        `json:"collected_files"`
	VolumesProcessed   []string   `json:"volumes_processed"`
}

// NewUSNManifest creates a new USN Journal manifest with basic information.
func NewUSNManifest(hostname string) *USNManifest {
	return &USNManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]USNItem, 0),
		Errors:             make([]USNError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
		VolumesProcessed:   make([]string, 0),
	}
}

// AddItem adds a successfully collected USN item to the manifest.
func (um *USNManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	um.Items = append(um.Items, USNItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	um.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (um *USNManifest) AddError(target, errorMsg string) {
	um.Errors = append(um.Errors, USNError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (um *USNManifest) IncrementTotalFiles() {
	um.TotalFiles++
}

// AddProcessedVolume adds a volume to the list of processed volumes.
func (um *USNManifest) AddProcessedVolume(volume string) {
	um.VolumesProcessed = append(um.VolumesProcessed, volume)
}

// WriteManifest writes the manifest to a JSON file.
func (um *USNManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(um, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}