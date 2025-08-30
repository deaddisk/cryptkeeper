// Package win_certificates provides certificate store and PKI information collection for cryptkeeper.
package win_certificates

import (
	"encoding/json"
	"os"
	"time"
)

// CertificateItem represents a collected certificate-related file.
type CertificateItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "cert_stores", "pki_config", "crypto_policies"
}

// CertificateError represents an error that occurred during collection.
type CertificateError struct {
	Target string `json:"target"` // What failed (e.g., specific store)
	Error  string `json:"error"`  // Error message
}

// CertificateManifest represents the complete manifest for certificates collection.
type CertificateManifest struct {
	CreatedUTC         string              `json:"created_utc"`
	Host               string              `json:"host"`
	CryptkeeperVersion string              `json:"cryptkeeper_version"`
	Items              []CertificateItem   `json:"items"`
	Errors             []CertificateError  `json:"errors"`
	TotalFiles         int                 `json:"total_files"`
	CollectedFiles     int                 `json:"collected_files"`
	CertificatesFound  int                 `json:"certificates_found"`
}

// NewCertificateManifest creates a new certificates manifest with basic information.
func NewCertificateManifest(hostname string) *CertificateManifest {
	return &CertificateManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]CertificateItem, 0),
		Errors:             make([]CertificateError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
		CertificatesFound:  0,
	}
}

// AddItem adds a successfully collected certificate item to the manifest.
func (cm *CertificateManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	cm.Items = append(cm.Items, CertificateItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	cm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (cm *CertificateManifest) AddError(target, errorMsg string) {
	cm.Errors = append(cm.Errors, CertificateError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (cm *CertificateManifest) IncrementTotalFiles() {
	cm.TotalFiles++
}

// SetCertificatesFound sets the number of certificates found.
func (cm *CertificateManifest) SetCertificatesFound(count int) {
	cm.CertificatesFound = count
}

// WriteManifest writes the manifest to a JSON file.
func (cm *CertificateManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(cm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}