package cli

import "testing"

func TestIsMalformedEmail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		// The rc25 walkthrough bug — user typed `vectis preflight` as
		// hostname, script derived `admin@vectis preflight` as email.
		// This is the exact class this guardrail exists to stop.
		{"space in domain (rc25 walkthrough bug)", "admin@vectis preflight", true},
		{"leading whitespace", " admin@foo.com", false}, // trimmed before check
		{"embedded tab", "admin@\tfoo.com", true},
		{"missing @", "adminfoo.com", true},
		{"empty local", "@foo.com", true},
		{"empty domain", "admin@", true},
		{"no dot in domain", "admin@localhost", true},
		{"valid FQDN domain", "admin@mail.example.com", false},
		{"valid simple FQDN", "admin@example.com", false},
		{"empty string", "", false}, // empty handled separately for clearer error
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isMalformedEmail(tc.in)
			if got != tc.want {
				t.Errorf("isMalformedEmail(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestIsPlaceholderEmail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"shipped default", "admin@example.com", true},
		{"historical placeholder", "my@example.com", true},
		{"uppercase example domain", "ADMIN@EXAMPLE.COM", true},
		{"leading whitespace", "  admin@example.com  ", true},
		{"subdomain of example.com is not example.com proper", "admin@mail.example.com", false},
		{"real address", "ops@vectismail.com", false},
		{"empty string", "", false}, // empty is handled separately for clearer error
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isPlaceholderEmail(tc.in)
			if got != tc.want {
				t.Errorf("isPlaceholderEmail(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}
