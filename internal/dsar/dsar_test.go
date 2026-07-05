package dsar

import (
	"testing"
	"time"
)

func TestSafePathSegment(t *testing.T) {
	safe := []string{"example.com", "john.doe", "sales", "a-b_c", "info+tag"}
	for _, s := range safe {
		if !safePathSegment(s) {
			t.Errorf("safePathSegment(%q) = false, want true", s)
		}
	}
	unsafe := []string{"", ".", "..", "../etc", "a/b", `a\b`, "..hidden", "foo/../bar", "a..b"}
	for _, s := range unsafe {
		if safePathSegment(s) {
			t.Errorf("safePathSegment(%q) = true, want false", s)
		}
	}
}

func TestMailRootFromLocation(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"maildir:/var/vectis/mail/%d/%n/Maildir", "/var/vectis/mail"},
		{"/var/vectis/mail/%d/%n/Maildir", "/var/vectis/mail"},
		{"maildir:/srv/mail/%u/Maildir", "/srv/mail"},
		{"maildir:/var/vectis/mail/", "/var/vectis/mail"},
		{"", "/var/vectis/mail"},                       // empty → default
		{"sdbox:relative/path/%d", "/var/vectis/mail"}, // non-absolute → default
	}
	for _, c := range cases {
		if got := MailRootFromLocation(c.in); got != c.want {
			t.Errorf("MailRootFromLocation(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestExportFilename(t *testing.T) {
	at := time.Date(2026, 6, 10, 9, 30, 0, 0, time.UTC)
	got := ExportFilename("alice@example.com", at)
	want := "vectis-dsar-alice_example.com-20260610.zip"
	if got != want {
		t.Errorf("ExportFilename = %q, want %q", got, want)
	}
	// Path-separator and other unsafe characters must be neutralised so the
	// filename can never escape the download directory.
	if got := ExportFilename("a/../b@x.io", at); got != "vectis-dsar-a_.._b_x.io-20260610.zip" {
		t.Errorf("unsafe ExportFilename not sanitised: %q", got)
	}
}

func TestSplitSubject(t *testing.T) {
	cases := []struct {
		in            string
		local, domain string
		ok            bool
	}{
		{"alice@example.com", "alice", "example.com", true},
		{"Bob.Smith@Example.COM", "Bob.Smith", "example.com", true}, // domain lower-cased, local preserved
		{"a@b@c.com", "a@b", "c.com", true},                         // last @ wins
		{"noatsign", "", "", false},
		{"@nolocal.com", "", "", false},
		{"trailing@", "", "", false},
	}
	for _, c := range cases {
		l, d, ok := splitSubject(c.in)
		if ok != c.ok || l != c.local || d != c.domain {
			t.Errorf("splitSubject(%q) = (%q,%q,%v), want (%q,%q,%v)", c.in, l, d, ok, c.local, c.domain, c.ok)
		}
	}
}
