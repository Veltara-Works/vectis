//go:build integration

package internal_test

// Integration test for the DSAR engine (export + erasure + tombstone
// reconcile). Lives in internal/ so CI's `go test -tags integration ./internal/`
// runs it against the CI Postgres. Mail bodies are exercised against a real
// on-disk Maildir created under t.TempDir(), which the service treats exactly
// as it treats the api container's mail-data mount.

import (
	"archive/zip"
	"bytes"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/dsar"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/Veltara-Works/vectis/internal/types"
)

func TestDSARExportEraseReconcile(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dbCfg := database.Config{
		Host:     envOr("VECTIS_TEST_PG_HOST", "127.0.0.1"),
		Port:     envOrInt("VECTIS_TEST_PG_PORT", 5432),
		Name:     envOr("VECTIS_TEST_PG_DB", "vectis"),
		User:     envOr("VECTIS_TEST_PG_USER", "postgres"),
		Password: envOr("VECTIS_TEST_PG_PASSWORD", "vectis_dev_super"),
	}
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()
	if err := database.RunMigrations(dbCfg.DSN(), logger); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	const domainName = "dsar-test.example"
	const localPart = "alice"
	subject := localPart + "@" + domainName

	domains := repository.NewDomainRepo(pool)
	mailboxes := repository.NewMailboxRepo(pool)
	aliases := repository.NewAliasRepo(pool)
	admins := repository.NewAdminRepo(pool)
	messages := repository.NewMessageRepo(pool)
	audit := repository.NewAuditRepo(pool)
	tombstones := repository.NewErasureTombstoneRepo(pool)

	// Clean any leftovers from a prior aborted run (deterministic re-runs).
	_, _ = pool.Exec(ctx, `DELETE FROM erasure_tombstones WHERE subject_email = $1`, subject)
	if old, _ := domains.GetByName(ctx, domainName); old != nil {
		_, _ = pool.Exec(ctx, `DELETE FROM messages WHERE domain_id = $1`, old.ID)
		_, _ = pool.Exec(ctx, `DELETE FROM aliases WHERE domain_id = $1`, old.ID)
		_, _ = pool.Exec(ctx, `DELETE FROM mailboxes WHERE domain_id = $1`, old.ID)
		_, _ = domains.Delete(ctx, old.ID)
	}

	dom, err := domains.Create(ctx, repository.DomainCreate{Name: domainName})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM erasure_tombstones WHERE subject_email = $1`, subject)
		_, _ = pool.Exec(bg, `DELETE FROM messages WHERE domain_id = $1`, dom.ID)
		_, _ = pool.Exec(bg, `DELETE FROM aliases WHERE domain_id = $1`, dom.ID)
		_, _ = pool.Exec(bg, `DELETE FROM mailboxes WHERE domain_id = $1`, dom.ID)
		_, _ = domains.Delete(bg, dom.ID)
	}()

	mb, err := mailboxes.Create(ctx, repository.MailboxCreate{
		DomainID: dom.ID, LocalPart: localPart, PasswordHash: "x",
	})
	if err != nil {
		t.Fatalf("create mailbox: %v", err)
	}

	if _, err := aliases.Create(ctx, repository.AliasCreate{
		DomainID: dom.ID, SourceLocalPart: "alias-of-alice", Destination: subject,
	}); err != nil {
		t.Fatalf("create alias: %v", err)
	}

	// One inbound (to the mailbox) and one outbound (from the subject).
	mkMsg := func(mailboxID *string, sender string, dir string) {
		m := &repository.Message{
			DomainID:   dom.ID,
			MailboxID:  mailboxID,
			MessageID:  "<" + types.NewUUIDv7() + "@" + domainName + ">",
			Direction:  dir,
			Sender:     sender,
			Recipients: []string{subject},
			Status:     "received",
			CreatedAt:  time.Now().UTC(),
		}
		if err := messages.Create(ctx, m); err != nil {
			t.Fatalf("create message: %v", err)
		}
	}
	mkMsg(&mb.ID, "outsider@other.example", "inbound")
	mkMsg(nil, subject, "outbound")

	// Real Maildir on disk: two stored messages.
	mailRoot := t.TempDir()
	maildir := filepath.Join(mailRoot, domainName, localPart, "Maildir")
	for _, sub := range []string{"cur", "new"} {
		if err := os.MkdirAll(filepath.Join(maildir, sub), 0o755); err != nil {
			t.Fatalf("mkdir maildir: %v", err)
		}
	}
	writeMail := func(sub, name, body string) {
		if err := os.WriteFile(filepath.Join(maildir, sub, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write mail: %v", err)
		}
	}
	writeMail("cur", "1700000000.M1.host", "Subject: hello\r\n\r\nstored body one\r\n")
	writeMail("new", "1700000001.M2.host", "Subject: world\r\n\r\nstored body two\r\n")

	svc := dsar.NewService(domains, mailboxes, aliases, admins, messages, audit, tombstones, mailRoot, logger)

	// --- Export ---
	var buf bytes.Buffer
	sum, err := svc.Export(ctx, subject, nil, &buf)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if sum.Messages != 2 {
		t.Errorf("export message metadata count = %d, want 2", sum.Messages)
	}
	if sum.MailFiles != 2 {
		t.Errorf("export mail files = %d, want 2", sum.MailFiles)
	}
	if sum.Aliases != 1 {
		t.Errorf("export aliases = %d, want 1", sum.Aliases)
	}

	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatalf("read export zip: %v", err)
	}
	want := map[string]bool{
		"account.json":                  false,
		"messages/cur/1700000000.M1.host.eml": false,
		"messages/new/1700000001.M2.host.eml": false,
	}
	for _, f := range zr.File {
		if _, ok := want[f.Name]; ok {
			want[f.Name] = true
		}
		if f.Name == "messages/cur/1700000000.M1.host.eml" {
			rc, _ := f.Open()
			b, _ := io.ReadAll(rc)
			rc.Close()
			if !bytes.Contains(b, []byte("stored body one")) {
				t.Errorf("exported mail body mismatch: %q", b)
			}
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("export zip missing entry %q", name)
		}
	}

	// --- Erase ---
	res, err := svc.Erase(ctx, subject, nil)
	if err != nil {
		t.Fatalf("erase: %v", err)
	}
	if res.MessageMetadata != 2 || res.Aliases != 1 || !res.MailboxDeleted || !res.MaildirRemoved {
		t.Fatalf("unexpected erase result: %+v", res)
	}
	if res.TombstoneID == "" {
		t.Fatal("erase did not record a tombstone")
	}
	if mb2, _ := mailboxes.GetByEmail(ctx, dom.ID, localPart); mb2 != nil {
		t.Error("mailbox should be gone after erase")
	}
	if _, statErr := os.Stat(maildir); !os.IsNotExist(statErr) {
		t.Error("maildir should be removed after erase")
	}
	var msgCount int
	pool.QueryRow(ctx, `SELECT count(*) FROM messages WHERE domain_id = $1`, dom.ID).Scan(&msgCount)
	if msgCount != 0 {
		t.Errorf("messages should be purged, %d remain", msgCount)
	}
	if tomb, _ := tombstones.GetBySubject(ctx, subject); tomb == nil {
		t.Error("tombstone should exist after erase")
	}

	// --- Reconcile after a simulated restore ---
	// Resurrect the mailbox + a message + the maildir, then reconcile.
	mb3, err := mailboxes.Create(ctx, repository.MailboxCreate{
		DomainID: dom.ID, LocalPart: localPart, PasswordHash: "x",
	})
	if err != nil {
		t.Fatalf("re-create mailbox (restore sim): %v", err)
	}
	mkMsg(&mb3.ID, "outsider@other.example", "inbound")
	if err := os.MkdirAll(filepath.Join(maildir, "new"), 0o755); err != nil {
		t.Fatalf("recreate maildir: %v", err)
	}
	writeMail("new", "1700000002.M3.host", "Subject: resurrected\r\n\r\nshould be purged\r\n")

	rsum, err := svc.ReconcileTombstones(ctx)
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if rsum.Resurrected < 1 {
		t.Errorf("reconcile should have re-applied at least one erasure, got %+v", rsum)
	}
	if mb4, _ := mailboxes.GetByEmail(ctx, dom.ID, localPart); mb4 != nil {
		t.Error("reconcile should have re-purged the resurrected mailbox")
	}
	if _, statErr := os.Stat(maildir); !os.IsNotExist(statErr) {
		t.Error("reconcile should have re-removed the resurrected maildir")
	}
	if tomb, _ := tombstones.GetBySubject(ctx, subject); tomb == nil || tomb.ReconcileRuns < 1 {
		t.Errorf("tombstone reconcile_runs should have incremented: %+v", tomb)
	}
}
