package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// TestVerifyRevokeSignature locks the revoke webhook's authentication core: a
// correct HMAC over the exact body passes; an empty secret, wrong key, tampered
// body, wrong scheme, non-hex, or wrong-length digest all fail. Empty-secret
// failure is the probe-resistance property (unconfigured == wrong key).
func TestVerifyRevokeSignature(t *testing.T) {
	secret := "test-webhook-secret"
	body := []byte(`{"event":"subscription.revoked","jti":"abc"}`)
	good := sign(secret, body)

	tests := []struct {
		name   string
		secret string
		body   []byte
		header string
		want   bool
	}{
		{"valid", secret, body, good, true},
		{"empty secret never verifies", "", body, good, false},
		{"wrong key", "other-secret", body, good, false},
		{"tampered body", secret, []byte(`{"event":"x"}`), good, false},
		{"missing header", secret, body, "", false},
		{"wrong scheme", secret, body, "md5=" + good[len("sha256="):], false},
		{"bare hex no scheme", secret, body, good[len("sha256="):], false},
		{"non-hex digest", secret, body, "sha256=zzzz", false},
		{"truncated digest (wrong length)", secret, body, "sha256=" + good[len("sha256="):len("sha256=")+10], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifyRevokeSignature(tt.secret, tt.body, tt.header); got != tt.want {
				t.Errorf("verifyRevokeSignature(%q, %q, %q) = %v, want %v",
					tt.secret, tt.body, tt.header, got, tt.want)
			}
		})
	}
}

// TestParseSHA256Signature covers the header parser in isolation.
func TestParseSHA256Signature(t *testing.T) {
	validHex := hex.EncodeToString(make([]byte, sha256.Size))
	if _, ok := parseSHA256Signature("sha256=" + validHex); !ok {
		t.Error("expected valid 32-byte sha256 digest to parse")
	}
	for _, bad := range []string{"", "sha256=", "sha1=" + validHex, validHex, "sha256=nothex", "sha256=dead"} {
		if _, ok := parseSHA256Signature(bad); ok {
			t.Errorf("expected %q to be rejected", bad)
		}
	}
}
