// Package secretcrypto provides authenticated encryption for small secrets
// stored at rest in the database (e.g. webhook signing secrets), using
// AES-256-GCM with a key derived from existing install key material.
//
// Values are stored as "enc:v1:" + base64(nonce || ciphertext). A value
// without the prefix is treated as legacy plaintext and returned verbatim by
// Decrypt, so the format can be rolled out over pre-existing rows without a
// flag day — see WebhookRepo.EncryptLegacySecrets for the one-shot migration.
package secretcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/hkdf"
)

// Prefix marks a value as encrypted by this package. The version segment lets
// us change the scheme later without ambiguity.
const Prefix = "enc:v1:"

// DeriveKey derives a 32-byte AES-256 key from a master secret and a label.
// The label provides domain separation so the derived key is independent of
// any other use of the same master secret (e.g. session/JWT signing).
func DeriveKey(master []byte, label string) []byte {
	r := hkdf.New(sha256.New, master, nil, []byte(label))
	key := make([]byte, 32)
	if _, err := io.ReadFull(r, key); err != nil {
		// HKDF-Expand over SHA-256 cannot fail for a 32-byte output; panic
		// here would only fire on a broken crypto runtime.
		panic(fmt.Sprintf("secretcrypto: deriving key: %v", err))
	}
	return key
}

// IsEncrypted reports whether value is in this package's encrypted format.
func IsEncrypted(value string) bool {
	return strings.HasPrefix(value, Prefix)
}

// Encrypt seals plaintext with AES-256-GCM under key and returns the
// prefixed, base64-encoded form.
func Encrypt(key []byte, plaintext string) (string, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secretcrypto: generate nonce: %w", err)
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return Prefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Decrypt reverses Encrypt. A value without Prefix is assumed to be legacy
// plaintext and returned unchanged, so callers can read rows written before
// encryption was introduced.
func Decrypt(key []byte, value string) (string, error) {
	if !IsEncrypted(value) {
		return value, nil
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(value, Prefix))
	if err != nil {
		return "", fmt.Errorf("secretcrypto: decode: %w", err)
	}
	gcm, err := newGCM(key)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(raw) < ns {
		return "", errors.New("secretcrypto: ciphertext too short")
	}
	nonce, ct := raw[:ns], raw[ns:]
	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("secretcrypto: open: %w", err)
	}
	return string(plaintext), nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretcrypto: new cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretcrypto: new gcm: %w", err)
	}
	return gcm, nil
}
