// Package win_firewall_net provides Windows firewall and network collection for cryptkeeper.
package win_firewall_net

import (
	"encoding/json"
	"os"
	"time"
)

// FirewallNetItem represents a collected firewall or network file.
type FirewallNetItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "firewall_log", "network_info"
}

// FirewallNetError represents an error that occurred during collection.
type FirewallNetError struct {
	Target string `json:"target"` // What failed (e.g., specific file path)
	Error  string `json:"error"`  // Error message
}

// FirewallNetManifest represents the complete manifest for firewall/network collection.
type FirewallNetManifest struct {
	CreatedUTC         string             `json:"created_utc"`
	Host               string             `json:"host"`
	CryptkeeperVersion string             `json:"cryptkeeper_version"`
	Items              []FirewallNetItem  `json:"items"`
	Errors             []FirewallNetError `json:"errors"`
	TotalFiles         int                `json:"total_files"`
	CollectedFiles     int                `json:"collected_files"`
}

// NewFirewallNetManifest creates a new firewall/network manifest with basic information.
func NewFirewallNetManifest(hostname string) *FirewallNetManifest {
	return &FirewallNetManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]FirewallNetItem, 0),
		Errors:             make([]FirewallNetError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected firewall/network item to the manifest.
func (fm *FirewallNetManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	fm.Items = append(fm.Items, FirewallNetItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	fm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (fm *FirewallNetManifest) AddError(target, errorMsg string) {
	fm.Errors = append(fm.Errors, FirewallNetError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (fm *FirewallNetManifest) IncrementTotalFiles() {
	fm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (fm *FirewallNetManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(fm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}