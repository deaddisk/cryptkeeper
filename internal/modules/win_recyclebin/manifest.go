// Package win_recyclebin provides Windows Recycle Bin collection for cryptkeeper.
package win_recyclebin

import ("encoding/json"; "os"; "time")

type RecycleBinItem struct {
	Path      string `json:"path"`
	Size      int64  `json:"size"`
	SHA256    string `json:"sha256"`
	Truncated bool   `json:"truncated"`
	Note      string `json:"note,omitempty"`
	Modified  string `json:"modified"`
	FileType  string `json:"file_type"` // "info_file", "recycle_file"
}

type RecycleBinError struct {
	Target string `json:"target"`
	Error  string `json:"error"`
}

type RecycleBinManifest struct {
	CreatedUTC         string            `json:"created_utc"`
	Host               string            `json:"host"`
	CryptkeeperVersion string            `json:"cryptkeeper_version"`
	Items              []RecycleBinItem  `json:"items"`
	Errors             []RecycleBinError `json:"errors"`
	TotalFiles         int               `json:"total_files"`
	CollectedFiles     int               `json:"collected_files"`
}

func NewRecycleBinManifest(hostname string) *RecycleBinManifest {
	return &RecycleBinManifest{
		CreatedUTC: time.Now().UTC().Format(time.RFC3339), Host: hostname, CryptkeeperVersion: "v0.1.0",
		Items: make([]RecycleBinItem, 0), Errors: make([]RecycleBinError, 0), TotalFiles: 0, CollectedFiles: 0,
	}
}

func (rm *RecycleBinManifest) AddItem(path string, size int64, sha256 string, truncated bool, modified time.Time, fileType, note string) {
	rm.Items = append(rm.Items, RecycleBinItem{Path: path, Size: size, SHA256: sha256, Truncated: truncated, Note: note, Modified: modified.UTC().Format(time.RFC3339), FileType: fileType})
	rm.CollectedFiles++
}

func (rm *RecycleBinManifest) AddError(target, errorMsg string) {
	rm.Errors = append(rm.Errors, RecycleBinError{Target: target, Error: errorMsg})
}

func (rm *RecycleBinManifest) IncrementTotalFiles() { rm.TotalFiles++ }

func (rm *RecycleBinManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(rm, "", "  ")
	if err != nil { return err }
	return os.WriteFile(manifestPath, data, 0644)
}