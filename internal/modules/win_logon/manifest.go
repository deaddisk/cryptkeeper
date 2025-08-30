// Package win_logon provides logon sessions and authentication data collection for cryptkeeper.
package win_logon

import (
	"encoding/json"
	"os"
	"time"
)

// LogonItem represents a collected logon session-related file.
type LogonItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "logon_sessions", "auth_history", "login_events"
}

// LogonError represents an error that occurred during collection.
type LogonError struct {
	Target string `json:"target"` // What failed (e.g., specific command)
	Error  string `json:"error"`  // Error message
}

// LogonManifest represents the complete manifest for logon sessions collection.
type LogonManifest struct {
	CreatedUTC         string       `json:"created_utc"`
	Host               string       `json:"host"`
	CryptkeeperVersion string       `json:"cryptkeeper_version"`
	Items              []LogonItem  `json:"items"`
	Errors             []LogonError `json:"errors"`
	TotalFiles         int          `json:"total_files"`
	CollectedFiles     int          `json:"collected_files"`
	ActiveSessionsFound int         `json:"active_sessions_found"`
}

// NewLogonManifest creates a new logon sessions manifest with basic information.
func NewLogonManifest(hostname string) *LogonManifest {
	return &LogonManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]LogonItem, 0),
		Errors:             make([]LogonError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
		ActiveSessionsFound: 0,
	}
}

// AddItem adds a successfully collected logon item to the manifest.
func (lm *LogonManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	lm.Items = append(lm.Items, LogonItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	lm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (lm *LogonManifest) AddError(target, errorMsg string) {
	lm.Errors = append(lm.Errors, LogonError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (lm *LogonManifest) IncrementTotalFiles() {
	lm.TotalFiles++
}

// SetActiveSessionsFound sets the number of active sessions found.
func (lm *LogonManifest) SetActiveSessionsFound(count int) {
	lm.ActiveSessionsFound = count
}

// WriteManifest writes the manifest to a JSON file.
func (lm *LogonManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(lm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}