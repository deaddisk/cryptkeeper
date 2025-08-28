// Package parse provides parsing, validation, and normalization utilities for cryptkeeper CLI.
package parse

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// NormalizeSince parses and normalizes a --since flag value.
// It accepts either RFC3339 timestamps or duration strings like "7d", "72h", "15m", "30s", "2w".
// For durations, it computes nowUTC - duration and returns the result as RFC3339.
// Returns the normalized RFC3339 string, whether the input was set, and any error.
func NormalizeSince(input string, now time.Time) (normalizedRFC3339 string, wasSet bool, err error) {
	if input == "" {
		return "", false, nil
	}

	// Try parsing as RFC3339 first
	if t, err := time.Parse(time.RFC3339, input); err == nil {
		return t.Format(time.RFC3339), true, nil
	}

	// Try parsing as duration
	duration, err := parseDurationWithWeeksAndDays(input)
	if err != nil {
		return "", true, fmt.Errorf("invalid --since: must be RFC3339 or a duration like 7d, 72h, 15m, 30s, 2w")
	}

	// Compute nowUTC - duration and format as RFC3339 (truncate to seconds)
	target := now.UTC().Add(-duration).Truncate(time.Second)
	return target.Format(time.RFC3339), true, nil
}

// parseDurationWithWeeksAndDays parses duration strings that may include weeks (w) and days (d).
// It extends Go's time.ParseDuration to support these additional units.
func parseDurationWithWeeksAndDays(s string) (time.Duration, error) {
	// Handle weeks and days by converting them to hours
	s = strings.ToLower(s)
	
	// Regular expression to find week and day units
	re := regexp.MustCompile(`(\d+(?:\.\d+)?)\s*([wd])`)
	
	// Convert weeks and days to hours
	converted := re.ReplaceAllStringFunc(s, func(match string) string {
		parts := re.FindStringSubmatch(match)
		if len(parts) != 3 {
			return match
		}
		
		value, err := strconv.ParseFloat(parts[1], 64)
		if err != nil {
			return match
		}
		
		unit := parts[2]
		switch unit {
		case "w":
			// 1 week = 7 days = 168 hours
			return fmt.Sprintf("%.0fh", value*168)
		case "d":
			// 1 day = 24 hours
			return fmt.Sprintf("%.0fh", value*24)
		default:
			return match
		}
	})
	
	// Now parse with Go's standard duration parser
	return time.ParseDuration(converted)
}