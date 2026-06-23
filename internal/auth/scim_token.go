package auth

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

const (
	// SCIMTokenPrefix identifies SCIM 2.0 provisioning bearer tokens
	// (distinguishes them from "vectis_" admin API keys and session tokens).
	SCIMTokenPrefix = "scim_"
	// scimTokenBytes is the number of random bytes in a token (32 = 64 hex chars).
	scimTokenBytes = 32
)

// GenerateSCIMToken creates a new random SCIM bearer token with the "scim_"
// prefix. Returns (rawToken, tokenHash, tokenPrefix). The raw token is shown to
// the operator exactly once at creation; only tokenHash is persisted. Hashing
// is shared with API keys (HashAPIKey = SHA-256 hex) — the distinct prefixes
// keep the two token spaces from colliding.
func GenerateSCIMToken() (rawToken, tokenHash, tokenPrefix string, err error) {
	b := make([]byte, scimTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate scim token: %w", err)
	}

	rawToken = SCIMTokenPrefix + hex.EncodeToString(b)
	tokenHash = HashAPIKey(rawToken)
	tokenPrefix = rawToken[:len(SCIMTokenPrefix)+8] // "scim_" + first 8 hex chars

	return rawToken, tokenHash, tokenPrefix, nil
}

// IsSCIMToken reports whether the token string looks like a SCIM bearer token.
func IsSCIMToken(token string) bool {
	return strings.HasPrefix(token, SCIMTokenPrefix)
}
