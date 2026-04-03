package types

import (
	"crypto/rand"
	"encoding/hex"

	"github.com/google/uuid"
)

// NewUUIDv7 generates a new UUIDv7 string.
func NewUUIDv7() string {
	return uuid.Must(uuid.NewV7()).String()
}

// NewVerificationToken generates a 32-byte hex-encoded random token
// for domain TXT verification.
func NewVerificationToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("failed to generate verification token: " + err.Error())
	}
	return "vectis-verify=" + hex.EncodeToString(b)
}
