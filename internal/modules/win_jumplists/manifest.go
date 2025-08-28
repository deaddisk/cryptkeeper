// Package win_jumplists provides Windows jump list collection for cryptkeeper.
package win_jumplists

import (
	"encoding/json"
	"os"
	"time"
)

// JumpListItem represents a collected jump list file.
type JumpListItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the jump list
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "automatic", "custom"
	Username  string `json:"username"`  // User who owns this jump list
}

// JumpListError represents an error that occurred during collection.
type JumpListError struct {
	Target string `json:"target"` // What failed (e.g., specific user or file path)
	Error  string `json:"error"`  // Error message
}

// JumpListManifest represents the complete manifest for jump list collection.
type JumpListManifest struct {
	CreatedUTC         string           `json:"created_utc"`
	Host               string           `json:"host"`
	CryptkeeperVersion string           `json:"cryptkeeper_version"`
	Items              []JumpListItem   `json:"items"`
	Errors             []JumpListError  `json:"errors"`
	UsersProcessed     int              `json:"users_processed"`
	TotalFiles         int              `json:"total_files"`
	CollectedFiles     int              `json:"collected_files"`
}

// NewJumpListManifest creates a new jump list manifest with basic information.
func NewJumpListManifest(hostname string) *JumpListManifest {
	return &JumpListManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]JumpListItem, 0),
		Errors:             make([]JumpListError, 0),
		UsersProcessed:     0,
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected jump list item to the manifest.
func (jm *JumpListManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, username, note string) {
	jm.Items = append(jm.Items, JumpListItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
		Username:  username,
	})
	jm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (jm *JumpListManifest) AddError(target, errorMsg string) {
	jm.Errors = append(jm.Errors, JumpListError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementUsersProcessed increments the count of users processed.
func (jm *JumpListManifest) IncrementUsersProcessed() {
	jm.UsersProcessed++
}

// IncrementTotalFiles increments the count of total files found.
func (jm *JumpListManifest) IncrementTotalFiles() {
	jm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (jm *JumpListManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(jm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}