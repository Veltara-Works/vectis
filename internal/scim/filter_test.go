package scim

import "testing"

func TestParseUserNameFilter(t *testing.T) {
	ok := map[string]string{
		`userName eq "jane@acme.example"`:  "jane@acme.example",
		`  userName   eq   "ops@x.test"  `: "ops@x.test",
		`USERNAME EQ "up@x.test"`:          "up@x.test", // case-insensitive
		`userName eq "a.b+tag@sub.x.test"`: "a.b+tag@sub.x.test",
	}
	for filter, want := range ok {
		got, matched := ParseUserNameFilter(filter)
		if !matched {
			t.Errorf("ParseUserNameFilter(%q) did not match", filter)
			continue
		}
		if got != want {
			t.Errorf("ParseUserNameFilter(%q) = %q, want %q", filter, got, want)
		}
	}

	for _, bad := range []string{
		"",
		`displayName eq "x"`,
		`userName co "x"`,       // unsupported operator
		`userName eq x`,         // unquoted
		`userName eq "x" and y`, // trailing
	} {
		if v, matched := ParseUserNameFilter(bad); matched {
			t.Errorf("ParseUserNameFilter(%q) matched unexpectedly (got %q)", bad, v)
		}
	}
}
