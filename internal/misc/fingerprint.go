package misc

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// APIKeyFingerprint returns the lowercase hex SHA-256 of a client API key, or an empty
// string for an empty key. Per-key usage accounting is indexed by fingerprint so the raw
// client key is never written to disk.
func APIKeyFingerprint(apiKey string) string {
	trimmed := strings.TrimSpace(apiKey)
	if trimmed == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(trimmed))
	return hex.EncodeToString(sum[:])
}
