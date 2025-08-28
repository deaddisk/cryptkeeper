// Package win_lnk provides Windows shortcut file collection for cryptkeeper.
package win_lnk

import (
	"encoding/json"
	"os"
	"time"
)

// LNKItem represents a collected LNK shortcut file.
type LNKItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the shortcut
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	Username  string `json:"username"`  // User who owns this shortcut
	Location  string `json:"location"`  // Location type: "recent", "desktop", "startmenu"
}

// LNKError represents an error that occurred during collection.
type LNKError struct {
	Target string `json:"target"` // What failed (e.g., specific user or file path)
	Error  string `json:"error"`  // Error message
}

// LNKManifest represents the complete manifest for LNK shortcut collection.
type LNKManifest struct {
	CreatedUTC         string    `json:"created_utc"`
	Host               string    `json:"host"`
	CryptkeeperVersion string    `json:"cryptkeeper_version"`
	Items              []LNKItem `json:"items"`
	Errors             []LNKError `json:"errors"`
	UsersProcessed     int       `json:"users_processed"`
	TotalFiles         int       `json:"total_files"`
	CollectedFiles     int       `json:"collected_files"`
}

// NewLNKManifest creates a new LNK shortcut manifest with basic information.
func NewLNKManifest(hostname string) *LNKManifest {
	return &LNKManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]LNKItem, 0),
		Errors:             make([]LNKError, 0),
		UsersProcessed:     0,
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected LNK item to the manifest.
func (lm *LNKManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, username, location, note string) {
	lm.Items = append(lm.Items, LNKItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		Username:  username,
		Location:  location,
	})
	lm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (lm *LNKManifest) AddError(target, errorMsg string) {
	lm.Errors = append(lm.Errors, LNKError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementUsersProcessed increments the count of users processed.
func (lm *LNKManifest) IncrementUsersProcessed() {
	lm.UsersProcessed++
}

// IncrementTotalFiles increments the count of total files found.
func (lm *LNKManifest) IncrementTotalFiles() {
	lm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (lm *LNKManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(lm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}