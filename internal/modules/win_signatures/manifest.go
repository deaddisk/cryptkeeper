// Package win_signatures provides file signatures and digital certificates collection for cryptkeeper.
package win_signatures

import (
	"encoding/json"
	"os"
	"time"
)

// SignatureItem represents a collected file signature-related file.
type SignatureItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "signatures", "certificates", "file_types"
}

// SignatureError represents an error that occurred during collection.
type SignatureError struct {
	Target string `json:"target"` // What failed (e.g., specific scan)
	Error  string `json:"error"`  // Error message
}

// SignatureManifest represents the complete manifest for file signatures collection.
type SignatureManifest struct {
	CreatedUTC         string            `json:"created_utc"`
	Host               string            `json:"host"`
	CryptkeeperVersion string            `json:"cryptkeeper_version"`
	Items              []SignatureItem   `json:"items"`
	Errors             []SignatureError  `json:"errors"`
	TotalFiles         int               `json:"total_files"`
	CollectedFiles     int               `json:"collected_files"`
	SignedFilesFound   int               `json:"signed_files_found"`
}

// NewSignatureManifest creates a new file signatures manifest with basic information.
func NewSignatureManifest(hostname string) *SignatureManifest {
	return &SignatureManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]SignatureItem, 0),
		Errors:             make([]SignatureError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
		SignedFilesFound:   0,
	}
}

// AddItem adds a successfully collected signature item to the manifest.
func (sm *SignatureManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	sm.Items = append(sm.Items, SignatureItem{
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
func (sm *SignatureManifest) AddError(target, errorMsg string) {
	sm.Errors = append(sm.Errors, SignatureError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (sm *SignatureManifest) IncrementTotalFiles() {
	sm.TotalFiles++
}

// SetSignedFilesFound sets the number of signed files found.
func (sm *SignatureManifest) SetSignedFilesFound(count int) {
	sm.SignedFilesFound = count
}

// WriteManifest writes the manifest to a JSON file.
func (sm *SignatureManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(sm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}