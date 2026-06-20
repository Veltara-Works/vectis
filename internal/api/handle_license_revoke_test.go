package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func macBytes(secret string, body []byte) []byte {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return mac.Sum(nil)
}

// TestValidRevokeMAC locks the revoke webhook's HMAC core (post header-parse): a
// correct MAC over the exact body passes; an empty secret, wrong key, or
// tampered body all fail. Empty-secret failure is the probe-resistance property
// (unconfigured == wrong key). Header-format rejection is covered separately by
// TestParseSHA256Signature.
func TestValidRevokeMAC(t *testing.T) {
	secret := "test-webhook-secret"
	body := []byte(`{"event":"subscription.revoked","jti":"abc"}`)
	good := macBytes(secret, body)

	tests := []struct {
		name     string
		secret   string
		body     []byte
		provided []byte
		want     bool
	}{
		{"valid", secret, body, good, true},
		{"empty secret never verifies", "", body, good, false},
		{"wrong key", "other-secret", body, good, false},
		{"tampered body", secret, []byte(`{"event":"x"}`), good, false},
		{"wrong-length mac", secret, body, good[:10], false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := validRevokeMAC(tt.secret, tt.body, tt.provided); got != tt.want {
				t.Errorf("validRevokeMAC(%q, %q, %x) = %v, want %v",
					tt.secret, tt.body, tt.provided, got, tt.want)
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
