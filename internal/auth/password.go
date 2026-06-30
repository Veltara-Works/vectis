package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters per Spec B (m=64MB, t=3, p=4).
const (
	argonMemory     = 65536 // 64 MB
	argonIterations = 3
	argonParallel   = 4
	argonSaltLen    = 16
	argonKeyLen     = 32
)

// HashPassword hashes a password using Argon2id and returns
// a PHC-format string: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallel, argonKeyLen)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory, argonIterations, argonParallel,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	), nil
}

// VerifyPassword checks a password against a PHC-format Argon2id hash.
func VerifyPassword(password, encoded string) (bool, error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid hash format")
	}

	var memory uint32
	var iterations uint32
	var parallelism uint8
	_, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	if err != nil {
		return false, fmt.Errorf("parse hash parameters: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}

	existingHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	computedHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(existingHash)))

	return subtle.ConstantTimeCompare(existingHash, computedHash) == 1, nil
}

// dummyPasswordHash is computed once at startup with the standard Argon2id
// params. The unknown-account login path verifies a submitted password against
// it (see VerifyDummyPassword) so an attacker cannot tell "no such admin" apart
// from "wrong password" by response latency — Argon2id dominates that latency,
// so skipping it for unknown accounts would leak which emails are real (#179).
// The plaintext is a fixed throwaway and never authenticates anyone.
var dummyPasswordHash = func() string {
	h, err := HashPassword("vectis-login-timing-equalizer")
	if err != nil {
		// HashPassword only fails if the RNG fails — effectively impossible.
		// Fall back to a structurally valid, standard-param hash so the dummy
		// verify still performs real Argon2id work and equalizes timing.
		return "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	}
	return h
}()

// VerifyDummyPassword runs a full Argon2id verification against a fixed dummy
// hash and discards the result. Call it on the unknown-account login path so
// that the response does the same KDF work a real password verify would,
// closing the user-enumeration timing side channel (#179).
func VerifyDummyPassword(password string) {
	_, _ = VerifyPassword(password, dummyPasswordHash)
}

// ValidatePasswordStrength checks that a password meets minimum complexity requirements.
// Returns nil if valid, or an error describing the issue.
func ValidatePasswordStrength(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}
	if len(password) > 128 {
		return fmt.Errorf("password must be at most 128 characters long")
	}
	return nil
}
