// Package win_ads provides Alternate Data Streams collection for cryptkeeper.
package win_ads

import (
	"encoding/json"
	"os"
	"time"
)

// ADSItem represents a collected Alternate Data Stream-related file.
type ADSItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "ads_scan", "stream_data", "metadata"
}

// ADSError represents an error that occurred during collection.
type ADSError struct {
	Target string `json:"target"` // What failed (e.g., specific directory)
	Error  string `json:"error"`  // Error message
}

// ADSManifest represents the complete manifest for ADS collection.
type ADSManifest struct {
	CreatedUTC         string     `json:"created_utc"`
	Host               string     `json:"host"`
	CryptkeeperVersion string     `json:"cryptkeeper_version"`
	Items              []ADSItem  `json:"items"`
	Errors             []ADSError `json:"errors"`
	TotalFiles         int        `json:"total_files"`
	CollectedFiles     int        `json:"collected_files"`
	StreamsFound       int        `json:"streams_found"`
}

// NewADSManifest creates a new ADS manifest with basic information.
func NewADSManifest(hostname string) *ADSManifest {
	return &ADSManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]ADSItem, 0),
		Errors:             make([]ADSError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
		StreamsFound:       0,
	}
}

// AddItem adds a successfully collected ADS item to the manifest.
func (am *ADSManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	am.Items = append(am.Items, ADSItem{
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
func (am *ADSManifest) AddError(target, errorMsg string) {
	am.Errors = append(am.Errors, ADSError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (am *ADSManifest) IncrementTotalFiles() {
	am.TotalFiles++
}

// SetStreamsFound sets the number of alternate data streams found.
func (am *ADSManifest) SetStreamsFound(count int) {
	am.StreamsFound = count
}

// WriteManifest writes the manifest to a JSON file.
func (am *ADSManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(am, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}