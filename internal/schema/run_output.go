// Package schema defines the data structures for cryptkeeper's output formats.
package schema

import (
	"time"
	
	"cryptkeeper/internal/core"
)

// RunOutput represents the complete JSON output structure for a harvest command execution.
type RunOutput struct {
	Command          string        `json:"command"`
	ArtifactsDir     string        `json:"artifacts_dir"`
	ArchivePath      string        `json:"archive_path"`
	Encrypted        bool          `json:"encrypted"`
	AgeRecipientSet  bool          `json:"age_recipient_set"`
	Parallelism      int           `json:"parallelism"`
	ModuleTimeout    string        `json:"module_timeout"`
	ModulesRun       []string      `json:"modules_run"`
	ModuleResults    []core.Result `json:"module_results"`
	FileCount        int           `json:"file_count"`
	BytesWritten     int64         `json:"bytes_written"`
	TimestampUTC     string        `json:"timestamp_utc"`
	
	// Optional fields for forward compatibility
	Since               string `json:"since,omitempty"`
	SinceNormalizedUTC  string `json:"since_normalized_utc,omitempty"`
}

// NewRunOutput creates a new RunOutput with the provided parameters.
func NewRunOutput(
	artifactsDir string,
	archivePath string,
	encrypted bool,
	ageRecipientSet bool,
	parallelism int,
	moduleTimeout time.Duration,
	modulesRun []string,
	moduleResults []core.Result,
	fileCount int,
	bytesWritten int64,
	timestamp time.Time,
) *RunOutput {
	return &RunOutput{
		Command:         "harvest",
		ArtifactsDir:    artifactsDir,
		ArchivePath:     archivePath,
		Encrypted:       encrypted,
		AgeRecipientSet: ageRecipientSet,
		Parallelism:     parallelism,
		ModuleTimeout:   moduleTimeout.String(),
		ModulesRun:      modulesRun,
		ModuleResults:   moduleResults,
		FileCount:       fileCount,
		BytesWritten:    bytesWritten,
		TimestampUTC:    timestamp.UTC().Format(time.RFC3339),
	}
}

// SetSince sets the since-related fields for the output.
func (ro *RunOutput) SetSince(since, sinceNormalized string) {
	if since != "" {
		ro.Since = since
	}
	if sinceNormalized != "" {
		ro.SinceNormalizedUTC = sinceNormalized
	}
}