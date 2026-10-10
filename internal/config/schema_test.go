package config

import "testing"

// TestDMARCEnforced locks in the default-ON semantics of rspamd.enforce_dmarc:
// a nil pointer (key absent, e.g. installs predating the field) must read as
// enabled, so upgrades start enforcing senders' DMARC policies.
func TestDMARCEnforced(t *testing.T) {
	tru, fls := true, false
	cases := []struct {
		name string
		ptr  *bool
		want bool
	}{
		{"absent/nil defaults on", nil, true},
		{"explicit true", &tru, true},
		{"explicit false scores only", &fls, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := RspamdConfig{EnforceDMARC: c.ptr}
			if got := r.DMARCEnforced(); got != c.want {
				t.Errorf("DMARCEnforced() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestSpamToJunkEnabled locks in the default-ON semantics of the
// rspamd.file_spam_to_junk flag: a nil pointer (key absent — e.g. installs
// predating the field) must read as enabled, so upgrades pick the feature up.
func TestSpamToJunkEnabled(t *testing.T) {
	tru, fls := true, false
	cases := []struct {
		name string
		ptr  *bool
		want bool
	}{
		{"absent/nil defaults on", nil, true},
		{"explicit true", &tru, true},
		{"explicit false opts out", &fls, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := RspamdConfig{FileSpamToJunk: c.ptr}
			if got := r.SpamToJunkEnabled(); got != c.want {
				t.Errorf("SpamToJunkEnabled() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestLocalResolverEnabled locks in the default-ON semantics of
// rspamd.local_resolver (ADR-026): installs without the key get the bundled
// resolver on upgrade.
func TestLocalResolverEnabled(t *testing.T) {
	tru, fls := true, false
	cases := []struct {
		name string
		ptr  *bool
		want bool
	}{
		{"absent/nil defaults on", nil, true},
		{"explicit true", &tru, true},
		{"explicit false opts out", &fls, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := RspamdConfig{LocalResolver: c.ptr}
			if got := r.LocalResolverEnabled(); got != c.want {
				t.Errorf("LocalResolverEnabled() = %v, want %v", got, c.want)
			}
		})
	}
}
