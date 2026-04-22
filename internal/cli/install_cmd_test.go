package cli

import "testing"

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
