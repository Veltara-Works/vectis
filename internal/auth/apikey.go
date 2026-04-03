package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// APIKeyPrefix identifies Vectis API keys (distinguishes from session tokens).
	APIKeyPrefix = "vectis_"
	// apiKeyBytes is the number of random bytes in a key (32 = 64 hex chars).
	apiKeyBytes = 32
)

// GenerateAPIKey creates a new random API key with the "vectis_" prefix.
// Returns (rawKey, keyHash, keyPrefix).
func GenerateAPIKey() (rawKey, keyHash, keyPrefix string, err error) {
	b := make([]byte, apiKeyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate api key: %w", err)
	}

	rawKey = APIKeyPrefix + hex.EncodeToString(b)
	keyHash = HashAPIKey(rawKey)
	keyPrefix = rawKey[:len(APIKeyPrefix)+8] // "vectis_" + first 8 hex chars

	return rawKey, keyHash, keyPrefix, nil
}

// HashAPIKey returns the SHA-256 hex digest of a raw API key.
func HashAPIKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}

// IsAPIKey returns true if the token string looks like a Vectis API key.
func IsAPIKey(token string) bool {
	return strings.HasPrefix(token, APIKeyPrefix)
}
