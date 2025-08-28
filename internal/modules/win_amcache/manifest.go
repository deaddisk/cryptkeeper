// Package win_amcache provides Windows Amcache file collection for cryptkeeper.
package win_amcache

import (
	"encoding/json"
	"os"
	"time"
)

// AmcacheItem represents a collected Amcache-related file.
type AmcacheItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "amcache", "recentfilecache", etc.
}

// AmcacheError represents an error that occurred during collection.
type AmcacheError struct {
	Target string `json:"target"` // What failed (e.g., specific file path)
	Error  string `json:"error"`  // Error message
}

// AmcacheManifest represents the complete manifest for Amcache collection.
type AmcacheManifest struct {
	CreatedUTC         string         `json:"created_utc"`
	Host               string         `json:"host"`
	CryptkeeperVersion string         `json:"cryptkeeper_version"`
	Items              []AmcacheItem  `json:"items"`
	Errors             []AmcacheError `json:"errors"`
	AmcachePath        string         `json:"amcache_path"`
	LegacyPath         string         `json:"legacy_path,omitempty"`
}

// NewAmcacheManifest creates a new Amcache manifest with basic information.
func NewAmcacheManifest(hostname, amcachePath, legacyPath string) *AmcacheManifest {
	return &AmcacheManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]AmcacheItem, 0),
		Errors:             make([]AmcacheError, 0),
		AmcachePath:        amcachePath,
		LegacyPath:         legacyPath,
	}
}

// AddItem adds a successfully collected Amcache item to the manifest.
func (am *AmcacheManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	am.Items = append(am.Items, AmcacheItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
}

// AddError adds an error to the manifest for a failed collection.
func (am *AmcacheManifest) AddError(target, errorMsg string) {
	am.Errors = append(am.Errors, AmcacheError{
		Target: target,
		Error:  errorMsg,
	})
}

// WriteManifest writes the manifest to a JSON file.
func (am *AmcacheManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(am, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}