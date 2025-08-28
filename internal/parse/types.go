// Package parse provides parsing, validation, and normalization utilities for cryptkeeper CLI.
package parse

// HarvestOutput represents the JSON output structure for the harvest command.
type HarvestOutput struct {
	Command                string `json:"command"`
	DryRun                 bool   `json:"dry_run"`
	SinceInput             string `json:"since_input"`
	SinceNormalizedRFC3339 string `json:"since_normalized_rfc3339"`
	CapMB                  int    `json:"cap_mb"`
	S3PresignedSet         bool   `json:"s3_presigned_set"`
	SFTPSet                bool   `json:"sftp_set"`
	EncryptAgeSet          bool   `json:"encrypt_age_set"`
	UploadIntent           string `json:"upload_intent"`
	EncryptionRequired     bool   `json:"encryption_required"`
	EncryptionSupplied     bool   `json:"encryption_supplied"`
	ReadyToUpload          bool   `json:"ready_to_upload"`
	TimestampUTC           string `json:"timestamp_utc"`
}