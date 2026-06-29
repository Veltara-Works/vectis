package api

import "testing"

// TestDomainInScope locks the API-key domain-scoping decision used by
// canAccessDomain: an empty scope list = unscoped (all domains), otherwise the
// domain must be explicitly listed. This is the control that stops a
// domain-scoped key from reaching other domains' resources.
func TestDomainInScope(t *testing.T) {
	cases := []struct {
		name   string
		scoped []string
		domain string
		want   bool
	}{
		{"empty scope = all domains", nil, "d1", true},
		{"empty slice = all domains", []string{}, "d1", true},
		{"listed domain allowed", []string{"d1", "d2"}, "d2", true},
		{"unlisted domain denied", []string{"d1", "d2"}, "d3", false},
		{"single scope match", []string{"d1"}, "d1", true},
		{"single scope mismatch", []string{"d1"}, "d2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domainInScope(tc.scoped, tc.domain); got != tc.want {
				t.Fatalf("domainInScope(%v, %q) = %v, want %v", tc.scoped, tc.domain, got, tc.want)
			}
		})
	}
}
