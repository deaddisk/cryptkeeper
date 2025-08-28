// Package parse provides parsing, validation, and normalization utilities for cryptkeeper CLI.
package parse

import (
	"fmt"
	"strings"
)

// ValidateCapMB validates the --cap-mb flag value.
// Returns an error if the value is negative.
func ValidateCapMB(n int) error {
	if n < 0 {
		return fmt.Errorf("invalid --cap-mb: must be >= 0")
	}
	return nil
}

// ValidateS3URL validates the --s3-presigned flag value.
// Returns whether the value is set and any validation error.
func ValidateS3URL(s string) (set bool, err error) {
	if s == "" {
		return false, nil
	}
	
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return true, fmt.Errorf("invalid --s3-presigned: must start with http:// or https://")
	}
	
	return true, nil
}

// ValidateSFTPURI validates the --sftp flag value.
// Returns whether the value is set and any validation error.
func ValidateSFTPURI(s string) (set bool, err error) {
	if s == "" {
		return false, nil
	}
	
	if !strings.HasPrefix(s, "sftp://") {
		return true, fmt.Errorf("invalid --sftp: must start with sftp://")
	}
	
	return true, nil
}

// ValidateAgeKey validates the --encrypt-age flag value.
// Returns whether the value is set and any validation error.
// Set is true only if non-empty and starts with "age1".
func ValidateAgeKey(s string) (set bool, err error) {
	if s == "" {
		return false, nil
	}
	
	if !strings.HasPrefix(s, "age1") {
		return false, fmt.Errorf("invalid --encrypt-age: must start with age1")
	}
	
	return true, nil
}

// ComputePolicy determines encryption requirements and upload readiness based on upload intent.
// Returns whether encryption is required and whether the system is ready to upload.
func ComputePolicy(uploadIntent string, encryptAgeSet bool) (encryptionRequired bool, readyToUpload bool) {
	encryptionRequired = uploadIntent != "none"
	readyToUpload = encryptionRequired && encryptAgeSet
	return encryptionRequired, readyToUpload
}

// ComputeUploadIntent determines the upload intent based on which destination flags are set.
func ComputeUploadIntent(s3Set, sftpSet bool) string {
	if s3Set && sftpSet {
		return "both"
	} else if s3Set {
		return "s3"
	} else if sftpSet {
		return "sftp"
	}
	return "none"
}