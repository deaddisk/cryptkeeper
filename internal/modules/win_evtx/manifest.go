// Package win_evtx provides Windows Event Log collection for cryptkeeper.
package win_evtx

import (
	"encoding/json"
	"os"
	"time"
)

// ChannelFile represents information about an exported event log channel.
type ChannelFile struct {
	Channel string `json:"channel"`
	File    string `json:"file"`
	Size    int64  `json:"size"`
	SHA256  string `json:"sha256"`
}

// Manifest represents the metadata for collected Windows Event Logs.
type Manifest struct {
	ChannelFiles       []ChannelFile `json:"channel_files"`
	CreatedUTC         string        `json:"created_utc"`
	Host               string        `json:"host"`
	CryptkeeperVersion string        `json:"cryptkeeper_version"`
}

// WriteManifest creates and writes the manifest.json file with channel metadata.
func WriteManifest(manifestPath string, channelFiles []ChannelFile, hostname string) error {
	manifest := Manifest{
		ChannelFiles:       channelFiles,
		CreatedUTC:         time.Now().UTC().Format(time.RFC3339),
		Host:               hostname,
		CryptkeeperVersion: "v0.1.0",
	}

	// Marshal to JSON with pretty formatting
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}

	// Write to file
	return os.WriteFile(manifestPath, data, 0644)
}