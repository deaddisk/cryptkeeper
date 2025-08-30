// Package win_tokens provides access tokens and privileges collection for cryptkeeper.
package win_tokens

import (
	"encoding/json"
	"os"
	"time"
)

// TokenItem represents a collected access token-related file.
type TokenItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "access_tokens", "privileges", "token_groups"
}

// TokenError represents an error that occurred during collection.
type TokenError struct {
	Target string `json:"target"` // What failed (e.g., specific command)
	Error  string `json:"error"`  // Error message
}

// TokenManifest represents the complete manifest for access tokens collection.
type TokenManifest struct {
	CreatedUTC         string       `json:"created_utc"`
	Host               string       `json:"host"`
	CryptkeeperVersion string       `json:"cryptkeeper_version"`
	Items              []TokenItem  `json:"items"`
	Errors             []TokenError `json:"errors"`
	TotalFiles         int          `json:"total_files"`
	CollectedFiles     int          `json:"collected_files"`
}

// NewTokenManifest creates a new access tokens manifest with basic information.
func NewTokenManifest(hostname string) *TokenManifest {
	return &TokenManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]TokenItem, 0),
		Errors:             make([]TokenError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected token item to the manifest.
func (tm *TokenManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	tm.Items = append(tm.Items, TokenItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	tm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (tm *TokenManifest) AddError(target, errorMsg string) {
	tm.Errors = append(tm.Errors, TokenError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (tm *TokenManifest) IncrementTotalFiles() {
	tm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (tm *TokenManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(tm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}