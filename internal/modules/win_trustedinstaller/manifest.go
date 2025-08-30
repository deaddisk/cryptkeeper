// Package win_trustedinstaller provides TrustedInstaller and system integrity collection for cryptkeeper.
package win_trustedinstaller

import (
	"encoding/json"
	"os"
	"time"
)

// TrustedInstallerItem represents a collected TrustedInstaller-related file.
type TrustedInstallerItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "trusted_installer", "system_integrity", "wfp_info"
}

// TrustedInstallerError represents an error that occurred during collection.
type TrustedInstallerError struct {
	Target string `json:"target"` // What failed (e.g., specific check)
	Error  string `json:"error"`  // Error message
}

// TrustedInstallerManifest represents the complete manifest for TrustedInstaller collection.
type TrustedInstallerManifest struct {
	CreatedUTC         string                   `json:"created_utc"`
	Host               string                   `json:"host"`
	CryptkeeperVersion string                   `json:"cryptkeeper_version"`
	Items              []TrustedInstallerItem   `json:"items"`
	Errors             []TrustedInstallerError  `json:"errors"`
	TotalFiles         int                      `json:"total_files"`
	CollectedFiles     int                      `json:"collected_files"`
	IntegrityViolations int                     `json:"integrity_violations"`
}

// NewTrustedInstallerManifest creates a new TrustedInstaller manifest with basic information.
func NewTrustedInstallerManifest(hostname string) *TrustedInstallerManifest {
	return &TrustedInstallerManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]TrustedInstallerItem, 0),
		Errors:             make([]TrustedInstallerError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
		IntegrityViolations: 0,
	}
}

// AddItem adds a successfully collected TrustedInstaller item to the manifest.
func (tim *TrustedInstallerManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	tim.Items = append(tim.Items, TrustedInstallerItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	tim.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (tim *TrustedInstallerManifest) AddError(target, errorMsg string) {
	tim.Errors = append(tim.Errors, TrustedInstallerError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (tim *TrustedInstallerManifest) IncrementTotalFiles() {
	tim.TotalFiles++
}

// SetIntegrityViolations sets the number of integrity violations found.
func (tim *TrustedInstallerManifest) SetIntegrityViolations(count int) {
	tim.IntegrityViolations = count
}

// WriteManifest writes the manifest to a JSON file.
func (tim *TrustedInstallerManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(tim, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}