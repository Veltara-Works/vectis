package api

import (
	"context"
	"testing"
)

// TestValidateLicenseBaseURL locks the C-h1 SSRF hardening: the ValidonX
// base_url (which carries the service_key) may only be https to a public host,
// with loopback allowed as a local dev/self-host escape hatch.
func TestValidateLicenseBaseURL(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		ok   bool
	}{
		{"default https public", "https://api.validonx.com", true},
		{"https public with path", "https://api.validonx.com/v1", true},
		{"loopback http (dev/test)", "http://127.0.0.1:8080", true},
		{"loopback v6", "http://[::1]:9000", true},
		{"localhost name", "http://localhost:3000", true},
		{"cloud metadata link-local", "http://169.254.169.254/latest/meta-data", false},
		{"rfc1918 private", "https://10.0.0.5", false},
		{"rfc1918 192.168", "https://192.168.1.10:8443", false},
		{"unspecified", "https://0.0.0.0", false},
		{"http to public host (downgrade)", "http://api.validonx.com", false},
		{"bogus scheme", "gopher://api.validonx.com", false},
		{"no host", "not-a-url", false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateLicenseBaseURL(context.Background(), tc.raw)
			if tc.ok && err != nil {
				t.Fatalf("expected %q to be accepted, got error: %v", tc.raw, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("expected %q to be rejected, got nil error", tc.raw)
			}
		})
	}
}
