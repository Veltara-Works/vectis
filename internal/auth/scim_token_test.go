package auth

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestGenerateSCIMToken(t *testing.T) {
	raw, hash, prefix, err := GenerateSCIMToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// raw = "scim_" + 64 hex chars
	if !strings.HasPrefix(raw, SCIMTokenPrefix) {
		t.Errorf("raw token %q missing %q prefix", raw, SCIMTokenPrefix)
	}
	body := strings.TrimPrefix(raw, SCIMTokenPrefix)
	if len(body) != 64 {
		t.Errorf("raw token body = %d chars, want 64 hex", len(body))
	}
	if _, derr := hex.DecodeString(body); derr != nil {
		t.Errorf("raw token body is not hex: %v", derr)
	}

	// prefix = "scim_" + first 8 hex
	if want := raw[:len(SCIMTokenPrefix)+8]; prefix != want {
		t.Errorf("prefix = %q, want %q", prefix, want)
	}

	// hash = SHA-256 hex of the raw token (shared with API-key hashing).
	if hash != HashAPIKey(raw) {
		t.Errorf("hash %q != HashAPIKey(raw)", hash)
	}
	if len(hash) != 64 {
		t.Errorf("hash = %d chars, want 64 hex", len(hash))
	}

	// Detection: a SCIM token is a SCIM token and NOT an API key.
	if !IsSCIMToken(raw) {
		t.Error("IsSCIMToken(raw) = false, want true")
	}
	if IsAPIKey(raw) {
		t.Error("a scim_ token must not be detected as a vectis_ API key")
	}

	// Uniqueness across calls.
	raw2, hash2, _, _ := GenerateSCIMToken()
	if raw == raw2 {
		t.Error("two generated tokens are identical")
	}
	if hash == hash2 {
		t.Error("two generated token hashes are identical")
	}
}

func TestIsSCIMToken(t *testing.T) {
	cases := map[string]bool{
		"scim_deadbeef": true,
		"scim_":         true,
		"vectis_abc123": false,
		"bearerscim_x":  false,
		"":              false,
	}
	for tok, want := range cases {
		if got := IsSCIMToken(tok); got != want {
			t.Errorf("IsSCIMToken(%q) = %v, want %v", tok, got, want)
		}
	}
}
