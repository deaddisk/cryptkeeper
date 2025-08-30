// Package win_networkinfo provides Windows network information collection for cryptkeeper.
package win_networkinfo

import (
	"encoding/json"
	"os"
	"time"
)

// NetworkInfoItem represents a collected network information file.
type NetworkInfoItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "dns_cache", "network_connections", "arp_table", "smb_shares"
}

// NetworkInfoError represents an error that occurred during collection.
type NetworkInfoError struct {
	Target string `json:"target"` // What failed (e.g., specific command)
	Error  string `json:"error"`  // Error message
}

// NetworkInfoManifest represents the complete manifest for network information collection.
type NetworkInfoManifest struct {
	CreatedUTC         string              `json:"created_utc"`
	Host               string              `json:"host"`
	CryptkeeperVersion string              `json:"cryptkeeper_version"`
	Items              []NetworkInfoItem   `json:"items"`
	Errors             []NetworkInfoError  `json:"errors"`
	TotalFiles         int                 `json:"total_files"`
	CollectedFiles     int                 `json:"collected_files"`
}

// NewNetworkInfoManifest creates a new network information manifest with basic information.
func NewNetworkInfoManifest(hostname string) *NetworkInfoManifest {
	return &NetworkInfoManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]NetworkInfoItem, 0),
		Errors:             make([]NetworkInfoError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected network information item to the manifest.
func (nm *NetworkInfoManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	nm.Items = append(nm.Items, NetworkInfoItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	nm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (nm *NetworkInfoManifest) AddError(target, errorMsg string) {
	nm.Errors = append(nm.Errors, NetworkInfoError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (nm *NetworkInfoManifest) IncrementTotalFiles() {
	nm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (nm *NetworkInfoManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(nm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}