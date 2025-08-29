// Package win_iis provides Windows IIS logs collection for cryptkeeper.
package win_iis

import ("encoding/json"; "os"; "time")

type IISItem struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Truncated bool   `json:"truncated"`
	Note      string `json:"note,omitempty"`
	Modified  string `json:"modified"`
	FileType  string `json:"file_type"` // "web_log"
}

type IISError struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

type IISManifest struct {
	CreatedUTC         string     `json:"created_utc"`
	Host               string     `json:"host"`
	CryptkeeperVersion string     `json:"cryptkeeper_version"`
	Items              []IISItem  `json:"items"`
	Errors             []IISError `json:"errors"`
	TotalFiles         int        `json:"total_files"`
	CollectedFiles     int        `json:"collected_files"`
}

func NewIISManifest(hostname string) *IISManifest {
	return &IISManifest{
		CreatedUTC: time.Now().UTC().Format(time.RFC3339), Host: hostname, CryptkeeperVersion: "v0.1.0",
		Items: make([]IISItem, 0), Errors: make([]IISError, 0), TotalFiles: 0, CollectedFiles: 0,
	}
}

func (im *IISManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	im.Items = append(im.Items, IISItem{Path: path, Size: size, SHA256: sha256, Truncated: truncated, Note: note, Modified: modified.UTC().Format(time.RFC3339), FileType: fileType})
	im.CollectedFiles++
}

func (im *IISManifest) AddError(target, errorMsg string) {
	im.Errors = append(im.Errors, IISError{Target: target, Error: errorMsg})
}

func (im *IISManifest) IncrementTotalFiles() { im.TotalFiles++ }

func (im *IISManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(im, "", "  ")
	if err != nil { return err }
	return os.WriteFile(manifestPath, data, 0644)
}