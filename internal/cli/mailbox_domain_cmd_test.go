package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

func TestMailboxRowsForDomain(t *testing.T) {
	created := time.Date(2026, 7, 4, 10, 0, 0, 0, time.UTC)
	suspended := "abuse"
	mboxes := []repository.Mailbox{
		{LocalPart: "alice", QuotaMB: 1024, Active: true, CreatedAt: created},
		{LocalPart: "bob", QuotaMB: 2048, Active: false, SendSuspended: true, SendSuspendedReason: &suspended, CreatedAt: created},
	}

	rows := mailboxRowsForDomain("example.com", mboxes)
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Email != "alice@example.com" {
		t.Errorf("row0 email = %q, want alice@example.com", rows[0].Email)
	}
	if rows[0].QuotaMB != 1024 || !rows[0].Active || rows[0].SendSuspended {
		t.Errorf("row0 fields wrong: %+v", rows[0])
	}
	if rows[1].Email != "bob@example.com" {
		t.Errorf("row1 email = %q, want bob@example.com", rows[1].Email)
	}
	if rows[1].Active || !rows[1].SendSuspended {
		t.Errorf("row1 should be inactive+suspended: %+v", rows[1])
	}
}

func TestMailboxRowsForDomain_Empty(t *testing.T) {
	rows := mailboxRowsForDomain("example.com", nil)
	if rows == nil {
		t.Fatal("want non-nil empty slice (marshals to [] not null)")
	}
	if len(rows) != 0 {
		t.Fatalf("got %d rows, want 0", len(rows))
	}
}

func TestDomainDeleteBlockReason(t *testing.T) {
	tests := []struct {
		name         string
		mailboxCount int
		aliasCount   int
		wantEmpty    bool
		wantContains string
	}{
		{"clean", 0, 0, true, ""},
		{"mailboxes only", 3, 0, false, "3 mailbox(es)"},
		{"aliases only", 0, 2, false, "2 alias(es)"},
		{"both", 1, 4, false, "1 mailbox(es) and 4 alias(es)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := domainDeleteBlockReason(tt.mailboxCount, tt.aliasCount)
			if tt.wantEmpty {
				if got != "" {
					t.Errorf("domainDeleteBlockReason(%d,%d) = %q, want empty", tt.mailboxCount, tt.aliasCount, got)
				}
				return
			}
			if got == "" {
				t.Fatalf("domainDeleteBlockReason(%d,%d) = empty, want a reason", tt.mailboxCount, tt.aliasCount)
			}
			if !strings.Contains(got, tt.wantContains) {
				t.Errorf("domainDeleteBlockReason(%d,%d) = %q, want it to contain %q",
					tt.mailboxCount, tt.aliasCount, got, tt.wantContains)
			}
		})
	}
}

func TestSplitEmailAddress(t *testing.T) {
	tests := []struct {
		in         string
		wantLocal  string
		wantDomain string
		wantOK     bool
	}{
		{"alice@example.com", "alice", "example.com", true},
		{"a.b+tag@sub.example.com", "a.b+tag", "sub.example.com", true},
		{"noatsign", "", "", false},
		{"@example.com", "", "", false},
		{"alice@", "", "", false},
		{"a@b@c", "", "", false},
		{"", "", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			local, domain, ok := splitEmailAddress(tt.in)
			if ok != tt.wantOK || local != tt.wantLocal || domain != tt.wantDomain {
				t.Errorf("splitEmailAddress(%q) = (%q,%q,%v), want (%q,%q,%v)",
					tt.in, local, domain, ok, tt.wantLocal, tt.wantDomain, tt.wantOK)
			}
		})
	}
}

// TestMailboxDomainCommandsRegistered guards against the phantom-command drift
// that this work fixed: the docs referenced `mailbox list` / `domain remove`
// before they existed. Assert they are wired under their parents with the
// expected flags.
func TestMailboxDomainCommandsRegistered(t *testing.T) {
	mboxList, _, err := mailboxCmd.Find([]string{"list"})
	if err != nil || mboxList.Name() != "list" {
		t.Fatalf("mailbox list not registered: cmd=%v err=%v", mboxList, err)
	}
	if mboxList.Flags().Lookup("domain") == nil {
		t.Error("mailbox list missing --domain flag")
	}

	mboxRemove, _, err := mailboxCmd.Find([]string{"remove"})
	if err != nil || mboxRemove.Name() != "remove" {
		t.Fatalf("mailbox remove not registered: cmd=%v err=%v", mboxRemove, err)
	}
	if mboxRemove.Flags().Lookup("email") == nil {
		t.Error("mailbox remove missing --email flag")
	}
	if mboxRemove.Flags().Lookup("confirm") == nil {
		t.Error("mailbox remove missing --confirm flag")
	}

	domRemove, _, err := domainCmd.Find([]string{"remove"})
	if err != nil || domRemove.Name() != "remove" {
		t.Fatalf("domain remove not registered: cmd=%v err=%v", domRemove, err)
	}
	if domRemove.Flags().Lookup("name") == nil {
		t.Error("domain remove missing --name flag")
	}
	if domRemove.Flags().Lookup("confirm") == nil {
		t.Error("domain remove missing --confirm flag")
	}
}
