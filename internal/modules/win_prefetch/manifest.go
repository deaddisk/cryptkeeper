// Package win_prefetch provides Windows prefetch file collection for cryptkeeper.
package win_prefetch

import (
	"encoding/json"
	"os"
	"time"
)

// PrefetchItem represents a collected prefetch file.
type PrefetchItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Optional notes about the prefetch file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
}

// PrefetchError represents an error that occurred during collection.
type PrefetchError struct {
	Target string `json:"target"` // What failed (e.g., specific .pf file path)
	Error  string `json:"error"`  // Error message
}

// PrefetchManifest represents the complete manifest for prefetch collection.
type PrefetchManifest struct {
	CreatedUTC           string          `json:"created_utc"`
	Host                 string          `json:"host"`
	CryptkeeperVersion   string          `json:"cryptkeeper_version"`
	Items                []PrefetchItem  `json:"items"`
	Errors               []PrefetchError `json:"errors"`
	PrefetchEnabled      bool            `json:"prefetch_enabled"`
	TotalFiles           int             `json:"total_files"`
	CollectedFiles       int             `json:"collected_files"`
	PrefetchPath         string          `json:"prefetch_path"`
}

// NewPrefetchManifest creates a new prefetch manifest with basic information.
func NewPrefetchManifest(hostname string, prefetchEnabled bool, prefetchPath string) *PrefetchManifest {
	return &PrefetchManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]PrefetchItem, 0),
		Errors:             make([]PrefetchError, 0),
		PrefetchEnabled:    prefetchEnabled,
		TotalFiles:         0,
		CollectedFiles:     0,
		PrefetchPath:       prefetchPath,
	}
}

// AddItem adds a successfully collected prefetch item to the manifest.
func (pm *PrefetchManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, note string) {
	pm.Items = append(pm.Items, PrefetchItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
	})
	pm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (pm *PrefetchManifest) AddError(target, errorMsg string) {
	pm.Errors = append(pm.Errors, PrefetchError{
		Target: target,
		Error:  errorMsg,
	})
}

// SetTotalFiles sets the total number of prefetch files found.
func (pm *PrefetchManifest) SetTotalFiles(total int) {
	pm.TotalFiles = total
}

// WriteManifest writes the manifest to a JSON file.
func (pm *PrefetchManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(pm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}