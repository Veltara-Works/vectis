package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// totpPeriodSeconds is the TOTP time-step (seconds per code).
	totpPeriodSeconds = 30
	// totpSkewSteps is how many periods of clock drift ValidateCodeWithSkew
	// tolerates on each side of the current step.
	totpSkewSteps = 1
)

// TOTPReplayWindow is the longest a single TOTP code stays acceptable under
// ValidateCodeWithSkew: period*(2*skew+1). A used-code cache must remember a
// code at least this long to fully block replay within the skew window.
const TOTPReplayWindow = totpPeriodSeconds * (2*totpSkewSteps + 1) * time.Second

// TOTPManager handles TOTP secret generation, encryption, and validation.
type TOTPManager struct {
	encryptionKey []byte // derived from API secret
	issuer        string
}

// NewTOTPManager creates a TOTP manager. The encryptionKey is derived from
// the API secret in secrets.yaml (SHA-256 to get exactly 32 bytes for AES-256).
func NewTOTPManager(apiSecret, issuer string) *TOTPManager {
	key := sha256.Sum256([]byte(apiSecret))
	return &TOTPManager{
		encryptionKey: key[:],
		issuer:        issuer,
	}
}

// GenerateSecret creates a new TOTP secret for the given admin email.
// Returns the encrypted secret (for DB storage) and the provisioning URI
// (for QR code generation).
func (tm *TOTPManager) GenerateSecret(email string) (encryptedSecret, provisioningURI string, err error) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      tm.issuer,
		AccountName: email,
		Period:      totpPeriodSeconds,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return "", "", fmt.Errorf("generate TOTP key: %w", err)
	}

	encrypted, err := tm.encrypt(key.Secret())
	if err != nil {
		return "", "", fmt.Errorf("encrypt TOTP secret: %w", err)
	}

	return encrypted, key.URL(), nil
}

// ValidateCode checks a TOTP code against an encrypted secret.
func (tm *TOTPManager) ValidateCode(encryptedSecret, code string) (bool, error) {
	secret, err := tm.decrypt(encryptedSecret)
	if err != nil {
		return false, fmt.Errorf("decrypt TOTP secret: %w", err)
	}

	return totp.Validate(code, secret), nil
}

// ValidateCodeWithSkew checks a TOTP code with a 1-period skew window
// (accepts current period +/- 1 to account for clock drift).
func (tm *TOTPManager) ValidateCodeWithSkew(encryptedSecret, code string) (bool, error) {
	secret, err := tm.decrypt(encryptedSecret)
	if err != nil {
		return false, fmt.Errorf("decrypt TOTP secret: %w", err)
	}

	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    totpPeriodSeconds,
		Skew:      totpSkewSteps,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	return valid, err
}

// encrypt uses AES-256-GCM to encrypt the TOTP secret. The nonce is
// prepended to the ciphertext, matching the backup encryption pattern.
func (tm *TOTPManager) encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(tm.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// decrypt reverses AES-256-GCM encryption.
func (tm *TOTPManager) decrypt(encoded string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}

	block, err := aes.NewCipher(tm.encryptionKey)
	if err != nil {
		return "", fmt.Errorf("create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}

	return string(plaintext), nil
}
