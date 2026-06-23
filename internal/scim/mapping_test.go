package scim

import (
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

func sp(s string) *string { return &s }

func TestMailboxToUser_Full(t *testing.T) {
	created := time.Date(2026, 6, 23, 10, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 6, 23, 11, 30, 0, 0, time.UTC)
	m := &repository.Mailbox{
		ID:          "mb-1",
		LocalPart:   "jane.doe",
		DisplayName: sp("Jane Doe"),
		Active:      true,
		CreatedAt:   created,
		UpdatedAt:   updated,
		ExternalID:  sp("okta-007"),
	}

	u := MailboxToUser(m, "acme.example", "https://mail.acme.example/")

	if len(u.Schemas) != 1 || u.Schemas[0] != UserSchema {
		t.Errorf("schemas = %v", u.Schemas)
	}
	if u.ID != "mb-1" {
		t.Errorf("id = %q", u.ID)
	}
	if u.UserName != "jane.doe@acme.example" {
		t.Errorf("userName = %q", u.UserName)
	}
	if u.ExternalID != "okta-007" {
		t.Errorf("externalId = %q", u.ExternalID)
	}
	if u.DisplayName != "Jane Doe" || u.Name == nil || u.Name.Formatted != "Jane Doe" {
		t.Errorf("displayName/name = %q / %+v", u.DisplayName, u.Name)
	}
	if !u.Active {
		t.Error("active = false, want true")
	}
	if len(u.Emails) != 1 || u.Emails[0].Value != "jane.doe@acme.example" || !u.Emails[0].Primary {
		t.Errorf("emails = %+v", u.Emails)
	}
	if u.Meta.ResourceType != ResourceTypeUser {
		t.Errorf("meta.resourceType = %q", u.Meta.ResourceType)
	}
	if u.Meta.Location != "https://mail.acme.example/scim/v2/Users/mb-1" {
		t.Errorf("meta.location = %q (base trailing slash must not double up)", u.Meta.Location)
	}
	if u.Meta.Created != "2026-06-23T10:00:00Z" {
		t.Errorf("meta.created = %q", u.Meta.Created)
	}
	if u.Meta.LastModified != "2026-06-23T11:30:00Z" {
		t.Errorf("meta.lastModified = %q", u.Meta.LastModified)
	}
}

func TestMailboxToUser_Minimal(t *testing.T) {
	m := &repository.Mailbox{
		ID:        "mb-2",
		LocalPart: "ops",
		Active:    false,
		CreatedAt: time.Unix(0, 0).UTC(),
		UpdatedAt: time.Unix(0, 0).UTC(),
		// no ExternalID, no DisplayName
	}
	u := MailboxToUser(m, "acme.example", "https://mail.acme.example")

	if u.ExternalID != "" {
		t.Errorf("externalId should be empty, got %q", u.ExternalID)
	}
	if u.Name != nil || u.DisplayName != "" {
		t.Errorf("name/displayName should be empty, got %+v / %q", u.Name, u.DisplayName)
	}
	if u.Active {
		t.Error("active = true, want false")
	}
	if u.Meta.Location != "https://mail.acme.example/scim/v2/Users/mb-2" {
		t.Errorf("meta.location = %q", u.Meta.Location)
	}
}

func TestSplitUserName(t *testing.T) {
	ok := map[string][2]string{
		"jane@acme.example":     {"jane", "acme.example"},
		"a.b+tag@sub.acme.test": {"a.b+tag", "sub.acme.test"},
	}
	for in, want := range ok {
		lp, dom, err := SplitUserName(in)
		if err != nil {
			t.Errorf("SplitUserName(%q) unexpected error: %v", in, err)
			continue
		}
		if lp != want[0] || dom != want[1] {
			t.Errorf("SplitUserName(%q) = (%q,%q), want (%q,%q)", in, lp, dom, want[0], want[1])
		}
	}

	for _, bad := range []string{"noat", "@domain.example", "local@", "", "@"} {
		if _, _, err := SplitUserName(bad); err == nil {
			t.Errorf("SplitUserName(%q) = nil error, want error", bad)
		}
	}
}
