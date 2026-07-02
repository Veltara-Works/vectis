//go:build integration

package repository_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// G-M1: DSAR erasure must match the subject's address case-insensitively. Mail
// is stored with the verbatim envelope address, so a message to/from a mixed-
// case address (John.Doe@corp.example) must still be erased and exported when
// the DSAR is issued for the canonical john.doe@corp.example — otherwise mixed-
// case mail survives an Art.17 erasure. LOWER() on both sides also matches
// already-stored rows, so no data-normalization migration is needed.
func TestMessageDeleteBySubject_CaseInsensitive(t *testing.T) {
	ctx := context.Background()
	domainRepo := repository.NewDomainRepo(testPool)
	repo := repository.NewMessageRepo(testPool)

	suffix := uniqueSuffix()
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "dsar-msg-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	headers, _ := json.Marshal(map[string]string{"X-Test": "yes"})
	mixed := "John.Doe@corp-" + suffix + ".example"
	canonical := "john.doe@corp-" + suffix + ".example"

	// Inbound-style row: recipient stored mixed-case, no mailbox link.
	recv := &repository.Message{
		DomainID:   domain.ID,
		MessageID:  "<recv-" + suffix + "@vectis.local>",
		Direction:  "inbound",
		Sender:     "ext@somewhere.example",
		Recipients: []string{mixed},
		Subject:    "to mixed-case recipient",
		Status:     "delivered",
		Headers:    headers,
		CreatedAt:  time.Now().UTC(),
	}
	if err := repo.Create(ctx, recv); err != nil {
		t.Fatalf("create inbound message: %v", err)
	}
	// Outbound-style row: sender stored mixed-case.
	sent := &repository.Message{
		DomainID:   domain.ID,
		MessageID:  "<sent-" + suffix + "@vectis.local>",
		Direction:  "outbound",
		Sender:     mixed,
		Recipients: []string{"ext@somewhere.example"},
		Subject:    "from mixed-case sender",
		Status:     "sent",
		Headers:    headers,
		CreatedAt:  time.Now().UTC(),
	}
	if err := repo.Create(ctx, sent); err != nil {
		t.Fatalf("create outbound message: %v", err)
	}

	// Export must also find the mixed-case rows via the canonical subject.
	listed, err := repo.ListBySubject(ctx, "", canonical)
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(listed) != 2 {
		t.Errorf("ListBySubject(canonical) matched %d rows, want 2 (mixed-case export leak)", len(listed))
	}

	n, err := repo.DeleteBySubject(ctx, "", canonical)
	if err != nil {
		t.Fatalf("DeleteBySubject: %v", err)
	}
	if n != 2 {
		t.Fatalf("DeleteBySubject(canonical) erased %d rows, want 2 (mixed-case mail survived Art.17 erasure)", n)
	}

	// Nothing must remain for the subject.
	remaining, err := repo.ListBySubject(ctx, "", canonical)
	if err != nil {
		t.Fatalf("ListBySubject after erase: %v", err)
	}
	if len(remaining) != 0 {
		t.Errorf("%d messages survived erasure", len(remaining))
	}
}

// U-1 (G-M1 gate): a mailbox provisioned with a mixed-case local part must still
// resolve for a DSAR issued against the canonical lowercase address. The DSAR
// resolve() gate calls GetByEmail (exact) then falls back to GetByEmailFold;
// without the fold, erase/export 404 with ErrSubjectNotFound and nothing is
// erased even though the repo-level SQL is case-insensitive.
func TestMailboxGetByEmailFold_CaseInsensitive(t *testing.T) {
	ctx := context.Background()
	domainRepo := repository.NewDomainRepo(testPool)
	repo := repository.NewMailboxRepo(testPool)

	suffix := uniqueSuffix()
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "mbox-fold-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	mb, err := repo.Create(ctx, repository.MailboxCreate{
		DomainID:     domain.ID,
		LocalPart:    "John.Doe",
		PasswordHash: "{PLAIN}dummy",
	})
	if err != nil {
		t.Fatalf("create mailbox: %v", err)
	}
	defer repo.Delete(ctx, mb.ID)

	// Exact-case lookup still works and is unaffected.
	if got, err := repo.GetByEmail(ctx, domain.ID, "John.Doe"); err != nil || got == nil {
		t.Fatalf("GetByEmail exact: got=%v err=%v", got, err)
	}
	// Canonical lowercase must miss the exact lookup...
	if got, err := repo.GetByEmail(ctx, domain.ID, "john.doe"); err != nil || got != nil {
		t.Fatalf("GetByEmail(lowercase) should miss exact-match: got=%v err=%v", got, err)
	}
	// ...but resolve via the fold lookup, returning the STORED mixed-case value.
	got, err := repo.GetByEmailFold(ctx, domain.ID, "john.doe")
	if err != nil {
		t.Fatalf("GetByEmailFold: %v", err)
	}
	if got == nil {
		t.Fatal("GetByEmailFold(john.doe) returned nil — mixed-case mailbox unresolvable for canonical DSAR (U-1)")
	}
	if got.LocalPart != "John.Doe" {
		t.Errorf("GetByEmailFold.LocalPart = %q, want stored case John.Doe", got.LocalPart)
	}
}

// G-M1b: forwarding-alias destinations are matched case-insensitively on erase
// and export, mirroring the message fix.
func TestAliasDeleteBySubject_CaseInsensitiveDestination(t *testing.T) {
	ctx := context.Background()
	domainRepo := repository.NewDomainRepo(testPool)
	repo := repository.NewAliasRepo(testPool)

	suffix := uniqueSuffix()
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "dsar-alias-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	mixed := "John.Doe@corp-" + suffix + ".example"
	canonical := "john.doe@corp-" + suffix + ".example"

	a, err := repo.Create(ctx, repository.AliasCreate{
		DomainID:        domain.ID,
		SourceLocalPart: "info",
		Destination:     mixed,
	})
	if err != nil {
		t.Fatalf("create alias: %v", err)
	}
	defer repo.Delete(ctx, a.ID)

	// Isolate the destination branch: a real domain UUID (as purge/export pass)
	// with a source local-part that does NOT match this alias, so the only way to
	// match is the case-insensitive destination clause (G-M1b).
	noSource := "not-the-source-" + suffix

	listed, err := repo.ListBySubject(ctx, domain.ID, noSource, canonical)
	if err != nil {
		t.Fatalf("ListBySubject: %v", err)
	}
	if len(listed) != 1 {
		t.Errorf("ListBySubject(canonical) matched %d aliases, want 1 (mixed-case destination export leak)", len(listed))
	}

	n, err := repo.DeleteBySubject(ctx, domain.ID, noSource, canonical)
	if err != nil {
		t.Fatalf("DeleteBySubject: %v", err)
	}
	if n != 1 {
		t.Fatalf("DeleteBySubject(canonical) erased %d aliases, want 1 (mixed-case forwarding survived erasure)", n)
	}
}
