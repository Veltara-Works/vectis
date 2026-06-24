package mailimport

import "testing"

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
