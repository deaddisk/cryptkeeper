// Package win_kerberos provides Kerberos authentication data collection for cryptkeeper.
package win_kerberos

import (
	"encoding/json"
	"os"
	"time"
)

// KerberosItem represents a collected Kerberos-related file.
type KerberosItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "kerberos_tickets", "krb_config", "ticket_cache"
}

// KerberosError represents an error that occurred during collection.
type KerberosError struct {
	Target string `json:"target"` // What failed (e.g., specific command)
	Error  string `json:"error"`  // Error message
}

// KerberosManifest represents the complete manifest for Kerberos collection.
type KerberosManifest struct {
	CreatedUTC         string           `json:"created_utc"`
	Host               string           `json:"host"`
	CryptkeeperVersion string           `json:"cryptkeeper_version"`
	Items              []KerberosItem   `json:"items"`
	Errors             []KerberosError  `json:"errors"`
	TotalFiles         int              `json:"total_files"`
	CollectedFiles     int              `json:"collected_files"`
	TicketsFound       int              `json:"tickets_found"`
}

// NewKerberosManifest creates a new Kerberos manifest with basic information.
func NewKerberosManifest(hostname string) *KerberosManifest {
	return &KerberosManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]KerberosItem, 0),
		Errors:             make([]KerberosError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
		TicketsFound:       0,
	}
}

// AddItem adds a successfully collected Kerberos item to the manifest.
func (km *KerberosManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	km.Items = append(km.Items, KerberosItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	km.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (km *KerberosManifest) AddError(target, errorMsg string) {
	km.Errors = append(km.Errors, KerberosError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (km *KerberosManifest) IncrementTotalFiles() {
	km.TotalFiles++
}

// SetTicketsFound sets the number of tickets found.
func (km *KerberosManifest) SetTicketsFound(count int) {
	km.TicketsFound = count
}

// WriteManifest writes the manifest to a JSON file.
func (km *KerberosManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(km, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}