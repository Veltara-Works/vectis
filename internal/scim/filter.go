package scim

import "regexp"

// userNameFilterRe matches the only filter Phase 1 supports: userName eq "x".
// Okta and Azure AD send exactly this to probe for an existing user before
// creating one. Case-insensitive on the attribute/operator per RFC 7644 §3.4.2.2.
var userNameFilterRe = regexp.MustCompile(`(?i)^\s*userName\s+eq\s+"([^"]+)"\s*$`)

// ParseUserNameFilter extracts the value from a `userName eq "value"` filter.
// Returns (value, true) on a match, ("", false) for an absent or unsupported
// filter (the handler then returns an empty ListResponse, never a 404).
func ParseUserNameFilter(filter string) (string, bool) {
	m := userNameFilterRe.FindStringSubmatch(filter)
	if m == nil {
		return "", false
	}
	return m[1], true
}
