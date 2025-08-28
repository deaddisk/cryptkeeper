// Package win_registry provides Windows registry hive collection for cryptkeeper.
package win_registry

import (
	"encoding/json"
	"os"
	"time"
)

// RegistryItem represents a collected registry hive or artifact.
type RegistryItem struct {
	Path      string `json:"path"`      // Relative path in the archive
	Size      int64  `json:"size"`      // File size in bytes
	SHA256    string `json:"sha256"`    // SHA-256 hash
	Truncated bool   `json:"truncated"` // Whether the file was truncated due to size limits
	Note      string `json:"note,omitempty"` // Optional notes (e.g., "system hive", "user hive")
	Method    string `json:"method,omitempty"` // Collection method: "copy" or "reg_export"
}

// RegistryError represents an error that occurred during collection.
type RegistryError struct {
	Target string `json:"target"` // What failed (e.g., "HKLM\SAM", "C:\Windows\System32\config\SYSTEM")
	Error  string `json:"error"`  // Error message
}

// RegistryManifest represents the complete manifest for registry collection.
type RegistryManifest struct {
	CreatedUTC           string          `json:"created_utc"`
	Host                 string          `json:"host"`
	CryptkeeperVersion   string          `json:"cryptkeeper_version"`
	Items                []RegistryItem  `json:"items"`
	Errors               []RegistryError `json:"errors"`
	BackupPrivilegeUsed  bool            `json:"backup_privilege_used"`
	RestorePrivilegeUsed bool            `json:"restore_privilege_used"`
}

// NewRegistryManifest creates a new registry manifest with basic information.
func NewRegistryManifest(hostname string, backupPriv, restorePriv bool) *RegistryManifest {
	return &RegistryManifest{
		CreatedUTC:           time.Now().UTC().Format(time.RFC3339),
		Host:                 hostname,
		CryptkeeperVersion:   "v0.1.0",
		Items:                make([]RegistryItem, 0),
		Errors:               make([]RegistryError, 0),
		BackupPrivilegeUsed:  backupPriv,
		RestorePrivilegeUsed: restorePriv,
	}
}

// AddItem adds a successfully collected registry item to the manifest.
func (rm *RegistryManifest) AddItem(path string, size int64, sha256 string, truncated bool, note, method string) {
	rm.Items = append(rm.Items, RegistryItem{
		Path:      path,
		Size:      size,
		SHA256:    sha256,
		Truncated: truncated,
		Note:      note,
		Method:    method,
	})
}

// AddError adds an error to the manifest for a failed collection.
func (rm *RegistryManifest) AddError(target, errorMsg string) {
	rm.Errors = append(rm.Errors, RegistryError{
		Target: target,
		Error:  errorMsg,
	})
}

// WriteManifest writes the manifest to a JSON file.
func (rm *RegistryManifest) WriteManifest(manifestPath string) error {
	data, err := json.MarshalIndent(rm, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(manifestPath, data, 0644)
}

// RegistryHive represents information about a registry hive to collect.
type RegistryHive struct {
	Name       string // Display name (e.g., "SYSTEM")
	FilePath   string // File path (e.g., "C:\Windows\System32\config\SYSTEM")
	RegKey     string // Registry key for reg.exe export (e.g., "HKLM\SYSTEM")
	Note       string // Description
	IsUserHive bool   // Whether this is a per-user hive
}

// GetSystemHives returns the list of system registry hives to collect.
func GetSystemHives() []RegistryHive {
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		systemRoot = "C:\\Windows"
	}
	
	configPath := systemRoot + "\\System32\\config\\"
	
	return []RegistryHive{
		{
			Name:     "SYSTEM",
			FilePath: configPath + "SYSTEM",
			RegKey:   "HKLM\\SYSTEM",
			Note:     "System configuration hive",
		},
		{
			Name:     "SOFTWARE",
			FilePath: configPath + "SOFTWARE",
			RegKey:   "HKLM\\SOFTWARE",
			Note:     "Software configuration hive",
		},
		{
			Name:     "SAM",
			FilePath: configPath + "SAM",
			RegKey:   "HKLM\\SAM",
			Note:     "Security Account Manager hive",
		},
		{
			Name:     "SECURITY",
			FilePath: configPath + "SECURITY",
			RegKey:   "HKLM\\SECURITY",
			Note:     "Security policy hive",
		},
		{
			Name:     "DEFAULT",
			FilePath: configPath + "DEFAULT",
			RegKey:   "HKU\\.DEFAULT",
			Note:     "Default user profile hive",
		},
	}
}

// GetUserHives returns registry hives for a specific user.
func GetUserHives(userProfilePath, username string) []RegistryHive {
	return []RegistryHive{
		{
			Name:       "NTUSER_" + username,
			FilePath:   userProfilePath + "\\NTUSER.DAT",
			RegKey:     "", // Not applicable for user hives via reg.exe
			Note:       "User profile hive for " + username,
			IsUserHive: true,
		},
		{
			Name:       "USRCLASS_" + username,
			FilePath:   userProfilePath + "\\AppData\\Local\\Microsoft\\Windows\\UsrClass.dat",
			RegKey:     "", // Not applicable
			Note:       "User classes hive for " + username,
			IsUserHive: true,
		},
	}
}