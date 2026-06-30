package mailimport

import (
	"strings"
	"testing"
)

func TestMapFolder(t *testing.T) {
	cases := []struct {
		name string
		f    Folder
		want string
	}{
		{"inbox preserved", Folder{Name: "INBOX"}, "INBOX"},
		{"inbox case-insensitive", Folder{Name: "Inbox"}, "INBOX"},
		{"special-use sent by attr", Folder{Name: "[Gmail]/Sent Mail", Delim: "/", Attrs: []string{"\\Sent"}}, "Sent"},
		{"special-use junk by attr", Folder{Name: "Spam", Attrs: []string{"\\Junk"}}, "Junk"},
		{"dot delimiter normalised", Folder{Name: "Work.Projects", Delim: "."}, "Work/Projects"},
		{"slash delimiter unchanged", Folder{Name: "Work/Projects", Delim: "/"}, "Work/Projects"},
		{"plain name passthrough", Folder{Name: "Receipts", Delim: "/"}, "Receipts"},
		{"unknown attr falls through to name", Folder{Name: "All", Delim: "/", Attrs: []string{"\\All"}}, "All"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := MapFolder(c.f, destSeparator); got != c.want {
				t.Errorf("MapFolder(%+v) = %q, want %q", c.f, got, c.want)
			}
		})
	}
}

func TestSanitizeFolderName(t *testing.T) {
	long := strings.Repeat("a", maxFolderNameLen+50)
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain passthrough", "Receipts", "Receipts"},
		{"hierarchy preserved", "Work/Projects", "Work/Projects"},
		{"non-ascii kept", "Wörk/Posteingang", "Wörk/Posteingang"},
		{"strips control chars", "Wo\x00rk\x1f", "Work"},
		{"strips CRLF (imap injection)", "Inbox\r\nA001 DELETE x", "InboxA001 DELETE x"},
		{"strips DEL", "Re\x7fceipts", "Receipts"},
		{"drops parent traversal component", "../../etc", "etc"},
		{"drops dot components", "a/./b/../c", "a/b/c"},
		{"empty becomes Imported", "", "Imported"},
		{"only-traversal becomes Imported", "../..", "Imported"},
		{"control-only becomes Imported", "\x01\x02\x03", "Imported"},
		{"length capped", long, strings.Repeat("a", maxFolderNameLen)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := sanitizeFolderName(c.in, destSeparator)
			if got != c.want {
				t.Errorf("sanitizeFolderName(%q) = %q, want %q", c.in, got, c.want)
			}
			if len(got) > maxFolderNameLen {
				t.Errorf("sanitizeFolderName(%q) len %d exceeds cap %d", c.in, len(got), maxFolderNameLen)
			}
		})
	}
}

func TestMapFolderSanitizesHostileNames(t *testing.T) {
	// A hostile source server can't inject control chars or traversal into the
	// destination mailbox name via MapFolder.
	got := MapFolder(Folder{Name: "ev\r\nil/../x", Delim: "/"}, destSeparator)
	if strings.ContainsAny(got, "\r\n") || strings.Contains(got, "..") {
		t.Errorf("MapFolder leaked unsafe chars: %q", got)
	}
}

func TestSanitizeFlags(t *testing.T) {
	got := sanitizeFlags([]string{"\\Seen", "\\Recent", "\\Flagged", "$Label1"})
	for _, f := range got {
		if f == "\\Recent" {
			t.Fatal("\\Recent must be stripped")
		}
	}
	if len(got) != 3 {
		t.Errorf("want 3 flags after stripping \\Recent, got %d (%v)", len(got), got)
	}
}
