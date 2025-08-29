// Package win_usb provides Windows USB device installation collection for cryptkeeper.
package win_usb

import (
	"encoding/json"
	"os"
	"time"
)

// USBItem represents a collected USB-related file.
type USBItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "device_log", "registry_note"
}

// USBError represents an error that occurred during collection.
type USBError struct {
	Target string `json:"target"` // What failed (e.g., specific file path)
	Error  string `json:"error"`  // Error message
}

// USBManifest represents the complete manifest for USB collection.
type USBManifest struct {
	CreatedUTC         string    `json:"created_utc"`
	Host               string    `json:"host"`
	CryptkeeperVersion string    `json:"cryptkeeper_version"`
	Items              []USBItem `json:"items"`
	Errors             []USBError `json:"errors"`
	TotalFiles         int       `json:"total_files"`
	CollectedFiles     int       `json:"collected_files"`
}

func NewUSBManifest(hostname string) *USBManifest {
	return &USBManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]USBItem, 0),
		Errors:             make([]USBError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

func (um *USBManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	um.Items = append(um.Items, USBItem{
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

func (um *USBManifest) AddError(target, errorMsg string) {
	um.Errors = append(um.Errors, USBError{
		Target: target,
		Error:  errorMsg,
	})
}

func (um *USBManifest) IncrementTotalFiles() {
	um.TotalFiles++
}

func (um *USBManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(um, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(manifestPath, data, 0644)
}