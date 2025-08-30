// Package win_vss provides Volume Shadow Copy Service (VSS) collection for cryptkeeper.
package win_vss

import (
	"encoding/json"
	"os"
	"time"
)

// VSSItem represents a collected Volume Shadow Copy-related file.
type VSSItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Description of the file
	Modified  string `json:"modified"`  // File modification time (RFC3339)
	FileType  string `json:"file_type"` // Type: "vss_info", "shadow_copies", "vss_config"
}

// VSSError represents an error that occurred during collection.
type VSSError struct {
	Target string `json:"target"` // What failed (e.g., specific operation)
	Error  string `json:"error"`  // Error message
}

// VSSManifest represents the complete manifest for VSS collection.
type VSSManifest struct {
	CreatedUTC         string     `json:"created_utc"`
	Host               string     `json:"host"`
	CryptkeeperVersion string     `json:"cryptkeeper_version"`
	Items              []VSSItem  `json:"items"`
	Errors             []VSSError `json:"errors"`
	TotalFiles         int        `json:"total_files"`
	CollectedFiles     int        `json:"collected_files"`
	ShadowCopiesFound  int        `json:"shadow_copies_found"`
}

// NewVSSManifest creates a new VSS manifest with basic information.
func NewVSSManifest(hostname string) *VSSManifest {
	return &VSSManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]VSSItem, 0),
		Errors:             make([]VSSError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
		ShadowCopiesFound:  0,
	}
}

// AddItem adds a successfully collected VSS item to the manifest.
func (vm *VSSManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	vm.Items = append(vm.Items, VSSItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Modified:  modified.UTC().Format(time.RFC3339),
		FileType:  fileType,
	})
	vm.CollectedFiles++
}

// AddError adds an error to the manifest for a failed collection.
func (vm *VSSManifest) AddError(target, errorMsg string) {
	vm.Errors = append(vm.Errors, VSSError{
		Target: target,
		Error:  errorMsg,
	})
}

// IncrementTotalFiles increments the count of total files found.
func (vm *VSSManifest) IncrementTotalFiles() {
	vm.TotalFiles++
}

// SetShadowCopiesFound sets the number of shadow copies found.
func (vm *VSSManifest) SetShadowCopiesFound(count int) {
	vm.ShadowCopiesFound = count
}

// WriteManifest writes the manifest to a JSON file.
func (vm *VSSManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(vm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}