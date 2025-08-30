// Package win_memory_process provides Windows memory and process artifacts collection for cryptkeeper.
package win_memory_process

import (
	"encoding/json"
	"os"
	"time"
)

// MemoryProcessItem represents a collected memory/process artifact file.
type MemoryProcessItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "pagefile", "process_list", "handles", "memory_info"
}

// MemoryProcessError represents an error that occurred during collection.
type MemoryProcessError struct {
	Target string `json:"target"` // What failed (e.g., specific command)
	Error  string `json:"error"`  // Error message
}

// MemoryProcessManifest represents the complete manifest for memory/process collection.
type MemoryProcessManifest struct {
	CreatedUTC         string                `json:"created_utc"`
	Host               string                `json:"host"`
	CryptkeeperVersion string                `json:"cryptkeeper_version"`
	Items              []MemoryProcessItem   `json:"items"`
	Errors             []MemoryProcessError  `json:"errors"`
	TotalFiles         int                   `json:"total_files"`
	CollectedFiles     int                   `json:"collected_files"`
}

// NewMemoryProcessManifest creates a new memory/process manifest with basic information.
func NewMemoryProcessManifest(hostname string) *MemoryProcessManifest {
	return &MemoryProcessManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]MemoryProcessItem, 0),
		Errors:             make([]MemoryProcessError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

// AddItem adds a successfully collected memory/process item to the manifest.
func (mm *MemoryProcessManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	mm.Items = append(mm.Items, MemoryProcessItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	mm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (mm *MemoryProcessManifest) AddError(target, errorMsg string) {
	mm.Errors = append(mm.Errors, MemoryProcessError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (mm *MemoryProcessManifest) IncrementTotalFiles() {
	mm.TotalFiles++
}

// WriteManifest writes the manifest to a JSON file.
func (mm *MemoryProcessManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(mm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}