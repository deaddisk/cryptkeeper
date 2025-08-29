// Package win_browser provides Windows browser artifacts collection for cryptkeeper.
package win_browser

import (
	"encoding/json"
	"os"
	"time"
)

type BrowserItem struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Truncated bool   `json:"truncated"`
	Note      string `json:"note,omitempty"`
	Modified  string `json:"modified"`
	FileType  string `json:"file_type"` // "history", "cookies", "login_data"
}

type BrowserError struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

type BrowserManifest struct {
	CreatedUTC         string         `json:"created_utc"`
	Host               string         `json:"host"`
	CryptkeeperVersion string         `json:"cryptkeeper_version"`
	Items              []BrowserItem  `json:"items"`
	Errors             []BrowserError `json:"errors"`
	TotalFiles         int            `json:"total_files"`
	CollectedFiles     int            `json:"collected_files"`
}

func NewBrowserManifest(hostname string) *BrowserManifest {
	return &BrowserManifest{
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
		Items:              make([]BrowserItem, 0),
		Errors:             make([]BrowserError, 0),
		TotalFiles:         0,
		CollectedFiles:     0,
	}
}

func (bm *BrowserManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	bm.Items = append(bm.Items, BrowserItem{
		Path: path, Size: size, SHA256: sha256, Truncated: truncated, Note: note,
		Modified: modified.UTC().Format(time.RFC3339), FileType: fileType,
	})
	bm.CollectedFiles++
}

func (bm *BrowserManifest) AddError(target, errorMsg string) {
	bm.Errors = append(bm.Errors, BrowserError{Target: target, Error: errorMsg})
}

func (bm *BrowserManifest) IncrementTotalFiles() { bm.TotalFiles++ }

func (bm *BrowserManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(bm, "", "  ")
	if err != nil { return err }
	return os.WriteFile(manifestPath, data, 0644)
}