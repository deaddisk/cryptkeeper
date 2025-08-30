// Package win_fileshares provides Windows file shares and permissions collection for cryptkeeper.
package win_fileshares

import (
	"encoding/json"
	"os"
	"time"
)

// FileShareItem represents a collected file share-related file.
type FileShareItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "shares_info", "permissions", "sessions"
}

// FileShareError represents an error that occurred during collection.
type FileShareError struct {
	Target string `json:"target"` // What failed (e.g., specific command)
	Error  string `json:"error"`  // Error message
}

// FileShareManifest represents the complete manifest for file shares collection.
type FileShareManifest struct {
	CreatedUTC         string           `json:"created_utc"`
	Host               string           `json:"host"`
	CryptkeeperVersion string           `json:"cryptkeeper_version"`
	Items              []FileShareItem  `json:"items"`
	Errors             []FileShareError `json:"errors"`
	TotalFiles         int              `json:"total_files"`
	CollectedFiles     int              `json:"collected_files"`
	SharesFound        int              `json:"shares_found"`
}

// NewFileShareManifest creates a new file share manifest with basic information.
func NewFileShareManifest(hostname string) *FileShareManifest {
	return &FileShareManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]FileShareItem, 0),
		Errors:             make([]FileShareError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
		SharesFound:        0,
	}
}

// AddItem adds a successfully collected file share item to the manifest.
func (fsm *FileShareManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	fsm.Items = append(fsm.Items, FileShareItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	fsm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (fsm *FileShareManifest) AddError(target, errorMsg string) {
	fsm.Errors = append(fsm.Errors, FileShareError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (fsm *FileShareManifest) IncrementTotalFiles() {
	fsm.TotalFiles++
}

// SetSharesFound sets the number of shares found.
func (fsm *FileShareManifest) SetSharesFound(count int) {
	fsm.SharesFound = count
}

// WriteManifest writes the manifest to a JSON file.
func (fsm *FileShareManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(fsm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}