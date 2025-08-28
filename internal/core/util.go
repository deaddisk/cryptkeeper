// Package core provides utility functions for cryptkeeper's collection framework.
package core

import (
	"os"
	"regexp"
	"strings"
)

// SanitizeName cleans a module name for safe use as a directory name.
// It removes or replaces characters that could be problematic in file paths.
func SanitizeName(name string) string {
	// Convert to lowercase for consistency
	name = strings.ToLower(name)
	
	// Replace problematic characters with underscores
	reg := regexp.MustCompile(`[^a-z0-9_-]`)
	name = reg.ReplaceAllString(name, "_")
	
	// Remove leading/trailing underscores and collapse multiple underscores
	name = strings.Trim(name, "_")
	reg = regexp.MustCompile(`_+`)
	name = reg.ReplaceAllString(name, "_")
	
	// Ensure we have something if the name was all invalid characters
	if name == "" {
		name = "unknown"
	}
	
	return name
}

// CreateTempDir creates a temporary directory for artifacts with a cryptkeeper prefix.
func CreateTempDir() (string, error) {
	return os.MkdirTemp("", "cryptkeeper_*")
}

// RemoveTempDir safely removes a temporary directory and its contents.
func RemoveTempDir(dir string) error {
	if dir == "" {
		return nil
	}
	return os.RemoveAll(dir)
}