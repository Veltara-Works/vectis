package mail

import "testing"

func TestValidateSieveName(t *testing.T) {
	valid := []string{
		"roundcube",
		"my filter",
		"vacation-2026",
		"règle", // non-ASCII printable is fine
		"a.b_c-d",
	}
	for _, name := range valid {
		if err := validateSieveName(name); err != nil {
			t.Errorf("validateSieveName(%q) = %v, want nil", name, err)
		}
	}

	invalid := map[string]string{
		"empty":           "",
		"embedded quote":  `evil" \r\nSETACTIVE "x`,
		"backslash":       `foo\bar`,
		"carriage return": "foo\rDELETESCRIPT \"x\"",
		"newline":         "foo\nSETACTIVE \"x\"",
		"null byte":       "foo\x00bar",
		"del control":     "foo\x7fbar",
	}
	for label, name := range invalid {
		if err := validateSieveName(name); err == nil {
			t.Errorf("validateSieveName rejected nothing for %s (%q), want error", label, name)
		}
	}

	// Over-long name is rejected.
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	if err := validateSieveName(string(long)); err == nil {
		t.Error("validateSieveName accepted a 129-byte name, want error")
	}
}

func TestParseSieveLiteral(t *testing.T) {
	ok := map[string]int{
		"{0}":     0,
		"{1}":     1,
		"{42}":    42,
		"{1234+}": 1234, // non-synchronizing literal marker
		"{0+}":    0,
	}
	for in, want := range ok {
		n, valid := parseSieveLiteral(in)
		if !valid || n != want {
			t.Errorf("parseSieveLiteral(%q) = (%d, %v), want (%d, true)", in, n, valid, want)
		}
	}

	notLiteral := []string{
		"OK",
		"NO script does not exist",
		"",
		"{}",        // no number
		"{-5}",      // negative
		"{12",       // unterminated
		"12}",       // no open brace
		"{1a}",      // non-numeric
		"{ 3 }",     // spaces not allowed
		`{5} "foo"`, // literal must be the whole line
	}
	for _, in := range notLiteral {
		if n, valid := parseSieveLiteral(in); valid {
			t.Errorf("parseSieveLiteral(%q) = (%d, true), want (_, false)", in, n)
		}
	}
}
