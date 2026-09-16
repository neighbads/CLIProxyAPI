package misc

import "strings"

// MatchWildcard reports whether value matches pattern, where '*' matches any
// substring (including the empty string). Matching is exact for every other
// character; callers that need case-insensitive matching must normalize both
// arguments themselves.
//
// Examples:
//
//	"gemini-*"      matches "gemini-2.5-pro"
//	"*-preview"     matches "gpt-5-preview"
//	"pro_0_2/*"     matches "pro_0_2/gpt-5.5"
//	"*"             matches everything
func MatchWildcard(pattern, value string) bool {
	if pattern == "" {
		return false
	}

	// Fast path for exact match (no wildcard present).
	if !strings.Contains(pattern, "*") {
		return pattern == value
	}

	parts := strings.Split(pattern, "*")
	// Handle prefix.
	if prefix := parts[0]; prefix != "" {
		if !strings.HasPrefix(value, prefix) {
			return false
		}
		value = value[len(prefix):]
	}

	// Handle suffix.
	if suffix := parts[len(parts)-1]; suffix != "" {
		if !strings.HasSuffix(value, suffix) {
			return false
		}
		value = value[:len(value)-len(suffix)]
	}

	// Handle middle segments in order.
	for i := 1; i < len(parts)-1; i++ {
		segment := parts[i]
		if segment == "" {
			continue
		}
		idx := strings.Index(value, segment)
		if idx < 0 {
			return false
		}
		value = value[idx+len(segment):]
	}

	return true
}
