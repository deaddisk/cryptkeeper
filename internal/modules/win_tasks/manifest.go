// Package win_tasks provides Windows Scheduled Tasks collection for cryptkeeper.
package win_tasks

import (
	"encoding/json"
	"os"
	"time"
)

// TaskItem represents a collected scheduled task file.
type TaskItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the task
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	TaskPath  string `json:"task_path"` // Original task path relative to Tasks root
}

// TaskError represents an error that occurred during collection.
type TaskError struct {
	Target string `json:"target"` // What failed (e.g., specific file path)
	Error  string `json:"error"`  // Error message
}

// TaskManifest represents the complete manifest for scheduled tasks collection.
type TaskManifest struct {
	CreatedUTC         string      `json:"created_utc"`
	Host               string      `json:"host"`
	CryptkeeperVersion string      `json:"cryptkeeper_version"`
	Items              []TaskItem  `json:"items"`
	Errors             []TaskError `json:"errors"`
	TotalFiles         int         `json:"total_files"`
	CollectedFiles     int         `json:"collected_files"`
	DirectoriesScanned int         `json:"directories_scanned"`
}

// NewTaskManifest creates a new scheduled tasks manifest with basic information.
func NewTaskManifest(hostname string) *TaskManifest {
	return &TaskManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]TaskItem, 0),
		Errors:             make([]TaskError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
		DirectoriesScanned: 0,
	}
}

// AddItem adds a successfully collected task item to the manifest.
func (tm *TaskManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, taskPath, note string) {
	tm.Items = append(tm.Items, TaskItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		TaskPath:  taskPath,
	})
	tm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (tm *TaskManifest) AddError(target, errorMsg string) {
	tm.Errors = append(tm.Errors, TaskError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (tm *TaskManifest) IncrementTotalFiles() {
	tm.TotalFiles++
}

// IncrementDirectoriesScanned increments the count of directories scanned.
func (tm *TaskManifest) IncrementDirectoriesScanned() {
	tm.DirectoriesScanned++
}

// WriteManifest writes the manifest to a JSON file.
func (tm *TaskManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(tm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}