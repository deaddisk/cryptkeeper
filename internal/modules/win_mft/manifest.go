// Package win_mft provides NTFS Master File Table (MFT) record collection for cryptkeeper.
package win_mft

import (
	"encoding/json"
	"os"
	"time"
)

// MFTItem represents a collected MFT-related file.
type MFTItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "mft_raw", "mft_parsed", "file_metadata"
}

// MFTError represents an error that occurred during collection.
type MFTError struct {
	Target string `json:"target"` // What failed (e.g., specific volume)
	Error  string `json:"error"`  // Error message
}

// MFTManifest represents the complete manifest for MFT collection.
type MFTManifest struct {
	CreatedUTC         string     `json:"created_utc"`
	Host               string     `json:"host"`
	CryptkeeperVersion string     `json:"cryptkeeper_version"`
	Items              []MFTItem  `json:"items"`
	Errors             []MFTError `json:"errors"`
	TotalFiles         int        `json:"total_files"`
	CollectedFiles     int        `json:"collected_files"`
	VolumesProcessed   []string   `json:"volumes_processed"`
}

// NewMFTManifest creates a new MFT manifest with basic information.
func NewMFTManifest(hostname string) *MFTManifest {
	return &MFTManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]MFTItem, 0),
		Errors:             make([]MFTError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
		VolumesProcessed:   make([]string, 0),
	}
}

// AddItem adds a successfully collected MFT item to the manifest.
func (mm *MFTManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	mm.Items = append(mm.Items, MFTItem{
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
func (mm *MFTManifest) AddError(target, errorMsg string) {
	mm.Errors = append(mm.Errors, MFTError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (mm *MFTManifest) IncrementTotalFiles() {
	mm.TotalFiles++
}

// AddProcessedVolume adds a volume to the list of processed volumes.
func (mm *MFTManifest) AddProcessedVolume(volume string) {
	mm.VolumesProcessed = append(mm.VolumesProcessed, volume)
}

// WriteManifest writes the manifest to a JSON file.
func (mm *MFTManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(mm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}