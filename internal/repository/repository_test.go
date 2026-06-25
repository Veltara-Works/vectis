//go:build integration

package repository_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/Veltara-Works/vectis/internal/secretcrypto"
	"github.com/Veltara-Works/vectis/internal/types"
)

var testWebhookKey = secretcrypto.DeriveKey([]byte("repo-test-master-secret"), "vectis-webhook-secret-v1")

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	dbCfg := database.Config{
		Host: "127.0.0.1", Port: 5432, Name: "vectis",
		User: "postgres", Password: "vectis_dev_super",
	}
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		slog.Error("skipping repository tests: cannot connect to postgres", "error", err)
		os.Exit(0)
	}
	testPool = pool
	code := m.Run()
	pool.Close()
	os.Exit(code)
}

// uniqueSuffix returns a per-test unique suffix so parallel runs and reruns
// don't collide on unique-constraint columns (domain names, admin emails).
func uniqueSuffix() string {
	return fmt.Sprintf("%d-%d", time.Now().UnixNano(), os.Getpid())
}

func TestAPIKey_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewAPIKeyRepo(testPool)

	adminRepo := repository.NewAdminRepo(testPool)
	suffix := uniqueSuffix()
	admin, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        "apikey-" + suffix + "@repo-test.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQ$dGVzdGhhc2g",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	defer adminRepo.Delete(ctx, admin.ID)

	key, err := repo.Create(ctx, repository.APIKeyCreate{
		AdminID:   admin.ID,
		Name:      "test-key",
		KeyHash:   "hash-" + suffix,
		KeyPrefix: "vkp_" + suffix[:8],
	})
	if err != nil {
		t.Fatalf("create api key: %v", err)
	}
	if key.ID == "" {
		t.Fatal("expected non-empty key ID")
	}

	got, err := repo.GetByID(ctx, key.ID)
	if err != nil {
		t.Fatalf("get api key: %v", err)
	}
	if got.Name != "test-key" {
		t.Errorf("name = %q, want test-key", got.Name)
	}

	keys, err := repo.ListByAdmin(ctx, admin.ID)
	if err != nil || len(keys) == 0 {
		t.Fatalf("list api keys: %v (count=%d)", err, len(keys))
	}

	ok, err := repo.Delete(ctx, key.ID)
	if err != nil {
		t.Fatalf("delete api key: %v", err)
	}
	if !ok {
		t.Error("Delete returned false for existing api key")
	}
}

func TestWebhook_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewWebhookRepo(testPool, testWebhookKey)
	adminRepo := repository.NewAdminRepo(testPool)

	suffix := uniqueSuffix()
	admin, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        "webhook-" + suffix + "@repo-test.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQ$dGVzdGhhc2g",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	defer adminRepo.Delete(ctx, admin.ID)

	plainSecret := "testsecret-" + suffix
	wh, err := repo.Create(ctx, repository.WebhookCreate{
		URL:       "https://example.com/hook/" + suffix,
		Secret:    plainSecret,
		Events:    []string{"domain.created", "mailbox.created"},
		CreatedBy: admin.ID,
	})
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}
	defer repo.Delete(ctx, wh.ID)

	if wh.URL == "" {
		t.Error("url should be set on returned webhook")
	}
	// Create -> GetByID round-trips the plaintext secret.
	if wh.Secret != plainSecret {
		t.Errorf("returned secret = %q, want decrypted %q", wh.Secret, plainSecret)
	}

	// The column is encrypted at rest, not plaintext (P5-M10).
	var stored string
	if err := testPool.QueryRow(ctx, `SELECT secret FROM webhooks WHERE id = $1`, wh.ID).Scan(&stored); err != nil {
		t.Fatalf("read raw secret: %v", err)
	}
	if !secretcrypto.IsEncrypted(stored) {
		t.Errorf("stored secret is not encrypted: %q", stored)
	}
	if strings.Contains(stored, plainSecret) {
		t.Error("stored secret leaks plaintext")
	}

	hooks, err := repo.ListAll(ctx)
	if err != nil {
		t.Fatalf("list webhooks: %v", err)
	}
	found := false
	for _, h := range hooks {
		if h.ID == wh.ID {
			found = true
			if h.Secret != plainSecret {
				t.Errorf("listed secret = %q, want decrypted %q", h.Secret, plainSecret)
			}
		}
	}
	if !found {
		t.Error("created webhook not found in list")
	}

	ok, err := repo.Delete(ctx, wh.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !ok {
		t.Error("Delete returned false for existing webhook")
	}
}

// TestWebhook_EncryptLegacySecrets verifies the idempotent startup migration
// encrypts a plaintext secret in place while preserving its value (P5-M10).
func TestWebhook_EncryptLegacySecrets(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewWebhookRepo(testPool, testWebhookKey)
	adminRepo := repository.NewAdminRepo(testPool)

	suffix := uniqueSuffix()
	admin, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        "wh-legacy-" + suffix + "@repo-test.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQ$dGVzdGhhc2g",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	defer adminRepo.Delete(ctx, admin.ID)

	// Insert a row with a PLAINTEXT secret, simulating a pre-encryption install.
	legacyID := types.NewUUIDv7()
	legacySecret := "legacy-plaintext-" + suffix
	if _, err := testPool.Exec(ctx,
		`INSERT INTO webhooks (id, domain_id, url, secret, events, active, created_by, created_at, updated_at)
		 VALUES ($1, NULL, $2, $3, $4, true, $5, NOW(), NOW())`,
		legacyID, "https://example.com/legacy/"+suffix, legacySecret,
		[]string{"mail.sent"}, admin.ID,
	); err != nil {
		t.Fatalf("insert legacy webhook: %v", err)
	}
	defer repo.Delete(ctx, legacyID)

	n, err := repo.EncryptLegacySecrets(ctx)
	if err != nil {
		t.Fatalf("encrypt legacy secrets: %v", err)
	}
	if n < 1 {
		t.Errorf("expected at least 1 row migrated, got %d", n)
	}

	// Column is now encrypted, but reads still yield the original plaintext.
	var stored string
	if err := testPool.QueryRow(ctx, `SELECT secret FROM webhooks WHERE id = $1`, legacyID).Scan(&stored); err != nil {
		t.Fatalf("read migrated secret: %v", err)
	}
	if !secretcrypto.IsEncrypted(stored) {
		t.Errorf("legacy secret not encrypted after migration: %q", stored)
	}
	got, err := repo.GetByID(ctx, legacyID)
	if err != nil {
		t.Fatalf("get migrated webhook: %v", err)
	}
	if got.Secret != legacySecret {
		t.Errorf("migrated secret decrypts to %q, want %q", got.Secret, legacySecret)
	}

	// Idempotent: a second pass migrates nothing new.
	n2, err := repo.EncryptLegacySecrets(ctx)
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	if n2 != 0 {
		t.Errorf("second pass migrated %d rows, want 0 (idempotent)", n2)
	}
}

func TestAlert_LogResolve(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewAlertRepo(testPool)

	dedup := "repo-test-" + uniqueSuffix()

	// No recent alert with this key yet.
	recent, err := repo.FindRecent(ctx, dedup, 1*time.Hour)
	if err != nil {
		t.Fatalf("find recent (empty): %v", err)
	}
	if recent != nil {
		t.Error("expected nil for unknown dedup key")
	}

	if err := repo.Log(ctx, "warning", "repo-test", "synthetic alert", dedup); err != nil {
		t.Fatalf("log alert: %v", err)
	}

	recent, err = repo.FindRecent(ctx, dedup, 1*time.Hour)
	if err != nil || recent == nil {
		t.Fatalf("find recent after log: %v, recent=%v", err, recent)
	}
	if recent.Message != "synthetic alert" {
		t.Errorf("message = %q, want synthetic alert", recent.Message)
	}
	if recent.ResolvedAt != nil {
		t.Error("new alert should have no ResolvedAt")
	}

	active, err := repo.ListActive(ctx)
	if err != nil {
		t.Fatalf("list active: %v", err)
	}
	foundActive := false
	for _, a := range active {
		if a.DedupKey == dedup {
			foundActive = true
		}
	}
	if !foundActive {
		t.Error("new alert not found in active list")
	}

	n, err := repo.Resolve(ctx, dedup)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if n != 1 {
		t.Errorf("resolve transitioned %d rows, want 1", n)
	}

	// After resolve, FindRecent still returns the row but with ResolvedAt set.
	after, err := repo.FindRecent(ctx, dedup, 1*time.Hour)
	if err != nil || after == nil {
		t.Fatalf("find recent after resolve: %v, after=%v", err, after)
	}
	if after.ResolvedAt == nil {
		t.Error("ResolvedAt should be set after Resolve")
	}

	// Resolving again is a no-op: nothing is still firing, so 0 rows transition.
	// The monitor relies on this to suppress repeat recovery notifications.
	n, err = repo.Resolve(ctx, dedup)
	if err != nil {
		t.Fatalf("resolve (idempotent): %v", err)
	}
	if n != 0 {
		t.Errorf("second resolve transitioned %d rows, want 0", n)
	}
}

func TestAdminDomain_CRUD(t *testing.T) {
	ctx := context.Background()

	adminRepo := repository.NewAdminRepo(testPool)
	domainRepo := repository.NewDomainRepo(testPool)
	adRepo := repository.NewAdminDomainRepo(testPool)

	suffix := uniqueSuffix()
	admin, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        "admindomain-" + suffix + "@repo-test.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQ$dGVzdGhhc2g",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	defer adminRepo.Delete(ctx, admin.ID)

	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "admin-domain-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	// No access before grant.
	has, err := adRepo.HasAccess(ctx, admin.ID, domain.ID)
	if err != nil {
		t.Fatalf("has access (pre): %v", err)
	}
	if has {
		t.Error("admin should not have access before Assign")
	}

	if err := adRepo.Assign(ctx, admin.ID, domain.ID); err != nil {
		t.Fatalf("assign: %v", err)
	}

	has, err = adRepo.HasAccess(ctx, admin.ID, domain.ID)
	if err != nil {
		t.Fatalf("has access (post): %v", err)
	}
	if !has {
		t.Error("admin should have access after Assign")
	}

	ids, err := adRepo.ListDomainIDs(ctx, admin.ID)
	if err != nil || len(ids) == 0 {
		t.Fatalf("list domain ids: %v (count=%d)", err, len(ids))
	}
	if ids[0] != domain.ID {
		t.Errorf("listed domain id = %q, want %q", ids[0], domain.ID)
	}

	if err := adRepo.Revoke(ctx, admin.ID, domain.ID); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	has, err = adRepo.HasAccess(ctx, admin.ID, domain.ID)
	if err != nil {
		t.Fatalf("has access (revoked): %v", err)
	}
	if has {
		t.Error("admin should not have access after Revoke")
	}
}

func TestDomain_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewDomainRepo(testPool)

	name := "crud-" + uniqueSuffix() + ".test"
	d, err := repo.Create(ctx, repository.DomainCreate{Name: name})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer repo.Delete(ctx, d.ID)

	if !d.Active {
		t.Error("new domain should be Active=true")
	}
	if d.SpamThreshold != 15.0 {
		t.Errorf("default spam_threshold = %v, want 15.0", d.SpamThreshold)
	}
	if d.VerificationStatus != "pending" {
		t.Errorf("initial verification_status = %q, want pending", d.VerificationStatus)
	}
	if d.VerificationToken == nil || *d.VerificationToken == "" {
		t.Error("new domain should have a verification token")
	}

	byID, err := repo.GetByID(ctx, d.ID)
	if err != nil || byID == nil {
		t.Fatalf("GetByID: %v, byID=%v", err, byID)
	}
	if byID.Name != name {
		t.Errorf("GetByID.Name = %q, want %q", byID.Name, name)
	}

	byName, err := repo.GetByName(ctx, name)
	if err != nil || byName == nil {
		t.Fatalf("GetByName: %v, byName=%v", err, byName)
	}
	if byName.ID != d.ID {
		t.Errorf("GetByName.ID = %q, want %q", byName.ID, d.ID)
	}

	// Missing name returns (nil, nil), not an error.
	missing, err := repo.GetByName(ctx, "nonexistent-"+uniqueSuffix()+".test")
	if err != nil {
		t.Fatalf("GetByName on missing: %v", err)
	}
	if missing != nil {
		t.Error("expected nil for missing domain lookup")
	}

	active := false
	threshold := 7.5
	updated, err := repo.Update(ctx, d.ID, repository.DomainUpdate{
		Active:        &active,
		SpamThreshold: &threshold,
	})
	if err != nil {
		t.Fatalf("update domain: %v", err)
	}
	if updated.Active {
		t.Error("Active should be false after update")
	}
	if updated.SpamThreshold != 7.5 {
		t.Errorf("SpamThreshold = %v, want 7.5", updated.SpamThreshold)
	}
	if !updated.UpdatedAt.After(d.UpdatedAt) {
		t.Error("UpdatedAt should advance on update")
	}

	count, err := repo.CountMailboxes(ctx, d.ID)
	if err != nil {
		t.Fatalf("count mailboxes: %v", err)
	}
	if count != 0 {
		t.Errorf("fresh domain mailbox count = %d, want 0", count)
	}

	ok, err := repo.Delete(ctx, d.ID)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !ok {
		t.Error("Delete returned false for existing domain")
	}
	ok, err = repo.Delete(ctx, d.ID)
	if err != nil {
		t.Fatalf("second delete: %v", err)
	}
	if ok {
		t.Error("Delete on missing domain should return false")
	}
}

func TestMessage_CRUD(t *testing.T) {
	ctx := context.Background()
	domainRepo := repository.NewDomainRepo(testPool)
	repo := repository.NewMessageRepo(testPool)

	suffix := uniqueSuffix()
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "msg-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	msgID := "<test-" + suffix + "@vectis.local>"
	headers, _ := json.Marshal(map[string]string{"X-Test": "yes"})
	m := &repository.Message{
		DomainID:   domain.ID,
		MessageID:  msgID,
		Direction:  "outbound",
		Sender:     "from@msg-" + suffix + ".test",
		Recipients: []string{"to@example.com"},
		Subject:    "hello from test",
		SizeBytes:  1234,
		Status:     "queued",
		Headers:    headers,
		CreatedAt:  time.Now().UTC(),
	}
	if err := repo.Create(ctx, m); err != nil {
		t.Fatalf("create message: %v", err)
	}
	if m.ID == "" {
		t.Fatal("Create should populate msg.ID")
	}

	byID, err := repo.GetByID(ctx, m.ID)
	if err != nil || byID == nil {
		t.Fatalf("GetByID: %v, byID=%v", err, byID)
	}
	if byID.MessageID != msgID {
		t.Errorf("GetByID.MessageID = %q, want %q", byID.MessageID, msgID)
	}
	if len(byID.Recipients) != 1 || byID.Recipients[0] != "to@example.com" {
		t.Errorf("Recipients = %v, want [to@example.com]", byID.Recipients)
	}

	byMsgID, err := repo.GetByMessageID(ctx, msgID)
	if err != nil || byMsgID == nil {
		t.Fatalf("GetByMessageID: %v, byMsgID=%v", err, byMsgID)
	}
	if byMsgID.ID != m.ID {
		t.Errorf("GetByMessageID.ID = %q, want %q", byMsgID.ID, m.ID)
	}

	missing, err := repo.GetByMessageID(ctx, "<nonexistent-"+suffix+"@v.local>")
	if err != nil {
		t.Fatalf("GetByMessageID on missing: %v", err)
	}
	if missing != nil {
		t.Error("expected nil for missing message lookup")
	}

	// List with domain filter must return the just-created row.
	list, err := repo.List(ctx, repository.MessageFilter{DomainID: domain.ID}, repository.PaginationParams{Limit: 10})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	found := false
	for _, lm := range list {
		if lm.ID == m.ID {
			found = true
		}
	}
	if !found {
		t.Error("created message not found in filtered list")
	}

	// Status-filter mismatch must exclude the row.
	list2, err := repo.List(ctx, repository.MessageFilter{DomainID: domain.ID, Status: "bounced"}, repository.PaginationParams{Limit: 10})
	if err != nil {
		t.Fatalf("list status filter: %v", err)
	}
	for _, lm := range list2 {
		if lm.ID == m.ID {
			t.Error("message with status=queued should not match status=bounced filter")
		}
	}

	// Direction filter.
	list3, err := repo.List(ctx, repository.MessageFilter{DomainID: domain.ID, Direction: "inbound"}, repository.PaginationParams{Limit: 10})
	if err != nil {
		t.Fatalf("list direction filter: %v", err)
	}
	for _, lm := range list3 {
		if lm.ID == m.ID {
			t.Error("outbound message should not match direction=inbound filter")
		}
	}

	if err := repo.UpdateStatus(ctx, m.ID, "delivered"); err != nil {
		t.Fatalf("update status: %v", err)
	}
	after, err := repo.GetByID(ctx, m.ID)
	if err != nil || after == nil {
		t.Fatalf("GetByID after update: %v", err)
	}
	if after.Status != "delivered" {
		t.Errorf("status after update = %q, want delivered", after.Status)
	}
}

func TestEmailEvent_Tracking(t *testing.T) {
	ctx := context.Background()
	domainRepo := repository.NewDomainRepo(testPool)
	msgRepo := repository.NewMessageRepo(testPool)
	repo := repository.NewEmailEventRepo(testPool)

	suffix := uniqueSuffix()
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "track-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	msgID := "<track-" + suffix + "@vectis.local>"
	m := &repository.Message{
		DomainID:   domain.ID,
		MessageID:  msgID,
		Direction:  "outbound",
		Sender:     "tracker@track-" + suffix + ".test",
		Recipients: []string{"rcpt@example.com"},
		Subject:    "track me",
		SizeBytes:  512,
		Status:     "sent",
		CreatedAt:  time.Now().UTC(),
	}
	if err := msgRepo.Create(ctx, m); err != nil {
		t.Fatalf("create message: %v", err)
	}

	ua := "Mozilla/5.0 test"
	ip1, ip2 := "10.0.0.1", "10.0.0.2"
	clickURL := "https://target.test/offer"
	now := time.Now().UTC()

	// Two opens from two IPs + one open reused from ip1 → unique_opens=2, opens=3.
	for _, ev := range []repository.EmailEvent{
		{DomainID: domain.ID, MessageID: msgID, EventType: "open", UserAgent: &ua, IPAddress: &ip1, CreatedAt: now},
		{DomainID: domain.ID, MessageID: msgID, EventType: "open", UserAgent: &ua, IPAddress: &ip2, CreatedAt: now.Add(1 * time.Second)},
		{DomainID: domain.ID, MessageID: msgID, EventType: "open", UserAgent: &ua, IPAddress: &ip1, CreatedAt: now.Add(2 * time.Second)},
		{DomainID: domain.ID, MessageID: msgID, EventType: "click", TargetURL: &clickURL, UserAgent: &ua, IPAddress: &ip1, CreatedAt: now.Add(3 * time.Second)},
	} {
		e := ev
		if err := repo.Create(ctx, &e); err != nil {
			t.Fatalf("create event %q: %v", e.EventType, err)
		}
	}

	eng, err := repo.GetMessageEngagement(ctx, msgID)
	if err != nil {
		t.Fatalf("get message engagement: %v", err)
	}
	if eng.Opens != 3 {
		t.Errorf("opens = %d, want 3", eng.Opens)
	}
	if eng.UniqueOpens != 2 {
		t.Errorf("unique_opens = %d, want 2", eng.UniqueOpens)
	}
	if eng.Clicks != 1 {
		t.Errorf("clicks = %d, want 1", eng.Clicks)
	}
	if eng.UniqueClicks != 1 {
		t.Errorf("unique_clicks = %d, want 1", eng.UniqueClicks)
	}
	if eng.FirstOpenAt == nil || eng.LastOpenAt == nil {
		t.Error("expected first/last open timestamps to be set")
	}
	if eng.FirstClickAt == nil {
		t.Error("expected first click timestamp to be set")
	}

	dAgg, err := repo.GetDomainEngagement(ctx, domain.ID, now.Add(-1*time.Hour), now.Add(1*time.Hour))
	if err != nil {
		t.Fatalf("get domain engagement: %v", err)
	}
	if dAgg.Opens != 3 || dAgg.Clicks != 1 {
		t.Errorf("domain engagement = (opens=%d, clicks=%d), want (3, 1)", dAgg.Opens, dAgg.Clicks)
	}
	if dAgg.MessagesOpened != 1 || dAgg.MessagesClicked != 1 {
		t.Errorf("domain engagement distinct msgs = (opened=%d, clicked=%d), want (1, 1)", dAgg.MessagesOpened, dAgg.MessagesClicked)
	}

	// Window that excludes all events should return zeroes.
	dAggEmpty, err := repo.GetDomainEngagement(ctx, domain.ID, now.Add(1*time.Hour), now.Add(2*time.Hour))
	if err != nil {
		t.Fatalf("get domain engagement empty window: %v", err)
	}
	if dAggEmpty.Opens != 0 || dAggEmpty.Clicks != 0 {
		t.Errorf("empty window engagement = (opens=%d, clicks=%d), want zeros", dAggEmpty.Opens, dAggEmpty.Clicks)
	}

	events, err := repo.ListByMessage(ctx, msgID, 10)
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	if len(events) != 4 {
		t.Errorf("event count = %d, want 4", len(events))
	}
	// Newest first — the click event was last inserted.
	if events[0].EventType != "click" {
		t.Errorf("newest event type = %q, want click", events[0].EventType)
	}

	// Limit honoured.
	limited, err := repo.ListByMessage(ctx, msgID, 2)
	if err != nil {
		t.Fatalf("list events limit: %v", err)
	}
	if len(limited) != 2 {
		t.Errorf("limited event count = %d, want 2", len(limited))
	}
}

// ---------- Mailbox / Alias ----------

func TestMailbox_CRUD(t *testing.T) {
	ctx := context.Background()
	domainRepo := repository.NewDomainRepo(testPool)
	repo := repository.NewMailboxRepo(testPool)

	suffix := uniqueSuffix()
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "mbox-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	quota := 512
	display := "Test User"
	mb, err := repo.Create(ctx, repository.MailboxCreate{
		DomainID:     domain.ID,
		LocalPart:    "alice",
		PasswordHash: "{PLAIN}dummy",
		DisplayName:  &display,
		QuotaMB:      &quota,
	})
	if err != nil {
		t.Fatalf("create mailbox: %v", err)
	}
	defer repo.Delete(ctx, mb.ID)

	if mb.QuotaMB != 512 {
		t.Errorf("QuotaMB = %d, want 512", mb.QuotaMB)
	}
	if !mb.Active {
		t.Error("new mailbox should be Active")
	}

	byID, err := repo.GetByID(ctx, mb.ID)
	if err != nil || byID == nil {
		t.Fatalf("GetByID: %v", err)
	}
	if byID.LocalPart != "alice" {
		t.Errorf("LocalPart = %q, want alice", byID.LocalPart)
	}

	byEmail, err := repo.GetByEmail(ctx, domain.ID, "alice")
	if err != nil || byEmail == nil {
		t.Fatalf("GetByEmail: %v", err)
	}
	if byEmail.ID != mb.ID {
		t.Errorf("GetByEmail.ID mismatch")
	}

	list, err := repo.ListByDomain(ctx, domain.ID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 || list[0].ID != mb.ID {
		t.Errorf("ListByDomain = %+v, want single mailbox %s", list, mb.ID)
	}

	inactive := false
	newQuota := 1024
	updated, err := repo.Update(ctx, mb.ID, repository.MailboxUpdate{
		Active:  &inactive,
		QuotaMB: &newQuota,
	})
	if err != nil || updated == nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Active {
		t.Error("Active should be false after update")
	}
	if updated.QuotaMB != 1024 {
		t.Errorf("QuotaMB after update = %d, want 1024", updated.QuotaMB)
	}

	ok, err := repo.Delete(ctx, mb.ID)
	if err != nil || !ok {
		t.Fatalf("delete: %v (ok=%v)", err, ok)
	}

	ok, _ = repo.Delete(ctx, mb.ID)
	if ok {
		t.Error("double delete should return false")
	}
}

func TestAlias_CRUD(t *testing.T) {
	ctx := context.Background()
	domainRepo := repository.NewDomainRepo(testPool)
	repo := repository.NewAliasRepo(testPool)

	suffix := uniqueSuffix()
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "alias-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	a, err := repo.Create(ctx, repository.AliasCreate{
		DomainID:        domain.ID,
		SourceLocalPart: "info",
		Destination:     "forward@example.com",
	})
	if err != nil {
		t.Fatalf("create alias: %v", err)
	}
	defer repo.Delete(ctx, a.ID)

	if a.Destination != "forward@example.com" {
		t.Errorf("Destination = %q", a.Destination)
	}

	bySrc, err := repo.GetBySource(ctx, domain.ID, "info")
	if err != nil || bySrc == nil {
		t.Fatalf("GetBySource: %v", err)
	}
	if bySrc.ID != a.ID {
		t.Error("GetBySource.ID mismatch")
	}

	list, err := repo.ListByDomain(ctx, domain.ID)
	if err != nil || len(list) != 1 {
		t.Fatalf("ListByDomain: %v (len=%d)", err, len(list))
	}

	newDest := "newforward@example.com"
	updated, err := repo.Update(ctx, a.ID, repository.AliasUpdate{Destination: &newDest})
	if err != nil || updated == nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Destination != newDest {
		t.Errorf("Destination after update = %q, want %q", updated.Destination, newDest)
	}

	ok, err := repo.Delete(ctx, a.ID)
	if err != nil || !ok {
		t.Fatalf("delete: %v", err)
	}
}

// ---------- Audit / Abuse / Backup ----------

func TestAudit_LogAndList(t *testing.T) {
	ctx := context.Background()
	domainRepo := repository.NewDomainRepo(testPool)
	repo := repository.NewAuditRepo(testPool)

	suffix := uniqueSuffix()
	// audit.resource_id is UUID, not free-form text — piggyback on a real
	// domain row to get a valid one.
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "audit-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	resourceID := domain.ID
	ip := "10.0.0.1"
	if err := repo.Log(ctx, nil, "domain.create", "domain", &resourceID,
		map[string]string{"note": "synthetic"}, &ip); err != nil {
		t.Fatalf("log audit: %v", err)
	}

	byRes, err := repo.ListByResource(ctx, "domain", resourceID, 10)
	if err != nil || len(byRes) == 0 {
		t.Fatalf("ListByResource: %v (len=%d)", err, len(byRes))
	}
	if byRes[0].Action != "domain.create" {
		t.Errorf("Action = %q, want domain.create", byRes[0].Action)
	}

	recent, err := repo.ListRecent(ctx, 20)
	if err != nil {
		t.Fatalf("ListRecent: %v", err)
	}
	foundRecent := false
	for _, e := range recent {
		if e.ResourceID != nil && *e.ResourceID == resourceID {
			foundRecent = true
		}
	}
	if !foundRecent {
		t.Error("just-logged entry not in ListRecent")
	}

	paged, err := repo.ListPaginated(ctx, "domain.create", "domain", "", repository.PaginationParams{Limit: 50})
	if err != nil {
		t.Fatalf("ListPaginated: %v", err)
	}
	foundPaged := false
	for _, e := range paged {
		if e.ResourceID != nil && *e.ResourceID == resourceID {
			foundPaged = true
		}
	}
	if !foundPaged {
		t.Error("just-logged entry not in ListPaginated with action+resource filter")
	}

	// Prune into the future — removes the entry we just created. Cheap
	// guarantee that the delete path at least runs; avoids a side-effect
	// on unrelated rows by not pruning far back.
	// Use a cutoff slightly after "now" to catch the row we just inserted.
	deleted, err := repo.DeleteOlderThan(ctx, time.Now().UTC().Add(1*time.Minute))
	if err != nil {
		t.Fatalf("DeleteOlderThan: %v", err)
	}
	if deleted < 1 {
		t.Errorf("DeleteOlderThan returned %d, expected >=1", deleted)
	}
}

func TestAbuse_SuspendCycle(t *testing.T) {
	ctx := context.Background()
	domainRepo := repository.NewDomainRepo(testPool)
	mbRepo := repository.NewMailboxRepo(testPool)
	adminRepo := repository.NewAdminRepo(testPool)
	repo := repository.NewAbuseRepo(testPool)

	suffix := uniqueSuffix()
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "abuse-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	mb, err := mbRepo.Create(ctx, repository.MailboxCreate{
		DomainID:     domain.ID,
		LocalPart:    "bad",
		PasswordHash: "{PLAIN}dummy",
	})
	if err != nil {
		t.Fatalf("create mailbox: %v", err)
	}
	defer mbRepo.Delete(ctx, mb.ID)

	admin, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        "abuse-" + suffix + "@repo-test.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQ$dGVzdGhhc2g",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	defer adminRepo.Delete(ctx, admin.ID)

	action := "suspend"
	evID, err := repo.LogEvent(ctx, &domain.ID, &mb.ID, "high_send_rate", "high",
		map[string]int{"rate": 1000}, &action)
	if err != nil || evID == "" {
		t.Fatalf("log event: %v (id=%q)", err, evID)
	}

	suspended, _, err := repo.IsMailboxSuspended(ctx, mb.ID)
	if err != nil {
		t.Fatalf("IsMailboxSuspended (pre): %v", err)
	}
	if suspended {
		t.Error("mailbox should not be suspended before Suspend")
	}

	if err := repo.SuspendMailbox(ctx, mb.ID, "auto: high send rate"); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	suspended, reason, err := repo.IsMailboxSuspended(ctx, mb.ID)
	if err != nil {
		t.Fatalf("IsMailboxSuspended (post): %v", err)
	}
	if !suspended {
		t.Error("mailbox should be suspended after Suspend")
	}
	if reason != "auto: high send rate" {
		t.Errorf("reason = %q", reason)
	}

	if err := repo.UnsuspendMailbox(ctx, mb.ID); err != nil {
		t.Fatalf("unsuspend: %v", err)
	}
	suspended, _, _ = repo.IsMailboxSuspended(ctx, mb.ID)
	if suspended {
		t.Error("mailbox should not be suspended after Unsuspend")
	}

	unresolved, err := repo.ListUnresolved(ctx, 50)
	if err != nil {
		t.Fatalf("ListUnresolved: %v", err)
	}
	foundUnresolved := false
	for _, e := range unresolved {
		if e.ID == evID {
			foundUnresolved = true
		}
	}
	if !foundUnresolved {
		t.Error("new event should appear in ListUnresolved")
	}

	if err := repo.Resolve(ctx, evID, admin.ID); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	unresolved2, _ := repo.ListUnresolved(ctx, 50)
	for _, e := range unresolved2 {
		if e.ID == evID {
			t.Error("resolved event should not be in ListUnresolved")
		}
	}
}

func TestBackup_Lifecycle(t *testing.T) {
	ctx := context.Background()
	adminRepo := repository.NewAdminRepo(testPool)
	repo := repository.NewBackupRepo(testPool)

	suffix := uniqueSuffix()
	// triggered_by FKs admins(id), so provision a throwaway admin.
	admin, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        "backup-" + suffix + "@repo-test.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQ$dGVzdGhhc2g",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	defer adminRepo.Delete(ctx, admin.ID)

	triggeredBy := admin.ID
	job, err := repo.Create(ctx, "create", &triggeredBy)
	if err != nil {
		t.Fatalf("create backup job: %v", err)
	}
	if job.Status != "pending" {
		t.Errorf("initial status = %q, want pending", job.Status)
	}

	if err := repo.UpdateProgress(ctx, job.ID, 50, "dumping postgres"); err != nil {
		t.Fatalf("update progress: %v", err)
	}
	mid, err := repo.GetByID(ctx, job.ID)
	if err != nil || mid == nil {
		t.Fatalf("GetByID mid: %v", err)
	}
	if mid.Progress != 50 {
		t.Errorf("Progress = %d, want 50", mid.Progress)
	}
	if mid.CurrentStep == nil || *mid.CurrentStep != "dumping postgres" {
		t.Error("CurrentStep not set")
	}

	if err := repo.Complete(ctx, job.ID, "/var/backups/test.tar.gz"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	done, err := repo.GetByID(ctx, job.ID)
	if err != nil || done == nil {
		t.Fatalf("GetByID done: %v", err)
	}
	if done.Status != "completed" {
		t.Errorf("status = %q, want completed", done.Status)
	}
	if done.CompletedAt == nil {
		t.Error("CompletedAt should be set")
	}
	if done.BackupPath == nil || *done.BackupPath != "/var/backups/test.tar.gz" {
		t.Error("BackupPath not set")
	}

	// Separate job to exercise the Fail path.
	job2, err := repo.Create(ctx, "create", &triggeredBy)
	if err != nil {
		t.Fatalf("create backup job 2: %v", err)
	}
	if err := repo.Fail(ctx, job2.ID, "disk full"); err != nil {
		t.Fatalf("fail: %v", err)
	}
	failed, _ := repo.GetByID(ctx, job2.ID)
	if failed.Status != "failed" {
		t.Errorf("status after Fail = %q", failed.Status)
	}
	if failed.ErrorMessage == nil || *failed.ErrorMessage != "disk full" {
		t.Error("ErrorMessage not set")
	}

	list, err := repo.List(ctx, 50)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	seen := 0
	for _, j := range list {
		if j.ID == job.ID || j.ID == job2.ID {
			seen++
		}
	}
	if seen != 2 {
		t.Errorf("expected both jobs in List, saw %d", seen)
	}
}

// ---------- FBLReport / IPWarmup / MailStats ----------

func TestFBLReport_CRUD(t *testing.T) {
	ctx := context.Background()
	domainRepo := repository.NewDomainRepo(testPool)
	repo := repository.NewFBLReportRepo(testPool)

	suffix := uniqueSuffix()
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "fbl-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	origMsgID := "<orig-" + suffix + "@v.local>"
	feedbackID := "fid-" + suffix
	details, _ := json.Marshal(map[string]string{"source-ip": "203.0.113.42"})
	id, err := repo.Create(ctx, &repository.FBLReport{
		DomainID:          &domain.ID,
		OriginalMessageID: &origMsgID,
		ReporterDomain:    "gmail.com",
		ComplaintType:     "abuse",
		FeedbackID:        &feedbackID,
		Details:           details,
	})
	if err != nil || id == "" {
		t.Fatalf("create fbl: %v (id=%q)", err, id)
	}

	byDomain, err := repo.ListByDomain(ctx, domain.ID, 10)
	if err != nil || len(byDomain) == 0 {
		t.Fatalf("ListByDomain: %v (len=%d)", err, len(byDomain))
	}
	if byDomain[0].ID != id {
		t.Error("ListByDomain.ID mismatch")
	}

	recent, err := repo.ListRecent(ctx, 10)
	if err != nil {
		t.Fatalf("ListRecent: %v", err)
	}
	foundRecent := false
	for _, r := range recent {
		if r.ID == id {
			foundRecent = true
		}
	}
	if !foundRecent {
		t.Error("new report not in ListRecent")
	}

	// Count within a window covering now.
	from := time.Now().UTC().Add(-1 * time.Hour)
	to := time.Now().UTC().Add(1 * time.Hour)
	count, err := repo.CountByDomain(ctx, domain.ID, from, to)
	if err != nil {
		t.Fatalf("CountByDomain: %v", err)
	}
	if count != 1 {
		t.Errorf("count = %d, want 1", count)
	}

	// Window that excludes our row.
	countEmpty, err := repo.CountByDomain(ctx, domain.ID, to, to.Add(1*time.Hour))
	if err != nil {
		t.Fatalf("CountByDomain empty: %v", err)
	}
	if countEmpty != 0 {
		t.Errorf("empty window count = %d, want 0", countEmpty)
	}
}

func TestIPWarmup_Lifecycle(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewIPWarmupRepo(testPool)

	suffix := uniqueSuffix()
	// Unique test IP per run — use 10.254.x.y so collisions are rare.
	ip := fmt.Sprintf("10.254.%d.%d", time.Now().Unix()%250, os.Getpid()%250)
	label := "warmup-" + suffix

	w, err := repo.Create(ctx, ip, label)
	if err != nil {
		t.Fatalf("create warmup: %v", err)
	}
	defer repo.Delete(ctx, w.ID)

	if w.WarmupDay != 1 {
		t.Errorf("initial WarmupDay = %d, want 1", w.WarmupDay)
	}
	if !w.Active {
		t.Error("new warmup should be active")
	}

	byIP, err := repo.GetByIP(ctx, ip)
	if err != nil || byIP == nil {
		t.Fatalf("GetByIP: %v", err)
	}
	if byIP.ID != w.ID {
		t.Error("GetByIP.ID mismatch")
	}

	list, err := repo.List(ctx)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	foundList := false
	for _, r := range list {
		if r.ID == w.ID {
			foundList = true
		}
	}
	if !foundList {
		t.Error("new warmup not in List")
	}

	if err := repo.IncrementSent(ctx, w.ID); err != nil {
		t.Fatalf("increment: %v", err)
	}
	afterInc, _ := repo.GetByIP(ctx, ip)
	if afterInc.DailySent != 1 {
		t.Errorf("DailySent after increment = %d, want 1", afterInc.DailySent)
	}

	if err := repo.AdvanceDay(ctx, w.ID, 2, 100); err != nil {
		t.Fatalf("advance day: %v", err)
	}
	afterAdv, _ := repo.GetByIP(ctx, ip)
	if afterAdv.WarmupDay != 2 || afterAdv.DailyLimit != 100 {
		t.Errorf("after advance = day=%d limit=%d, want 2/100", afterAdv.WarmupDay, afterAdv.DailyLimit)
	}
	if afterAdv.DailySent != 0 {
		t.Errorf("DailySent after advance = %d, want 0 (reset)", afterAdv.DailySent)
	}

	if err := repo.Deactivate(ctx, w.ID); err != nil {
		t.Fatalf("deactivate: %v", err)
	}
	afterDeact, _ := repo.GetByIP(ctx, ip)
	if afterDeact.Active {
		t.Error("Active should be false after Deactivate")
	}
}

func TestMailStats_IncrementAndAggregate(t *testing.T) {
	ctx := context.Background()
	domainRepo := repository.NewDomainRepo(testPool)
	repo := repository.NewMailStatsRepo(testPool)

	suffix := uniqueSuffix()
	domain, err := domainRepo.Create(ctx, repository.DomainCreate{Name: "stats-" + suffix + ".test"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	defer domainRepo.Delete(ctx, domain.ID)

	// Two sent + one bounce, with sizes.
	if err := repo.Increment(ctx, domain.ID, "sent", 1000); err != nil {
		t.Fatalf("increment sent 1: %v", err)
	}
	if err := repo.Increment(ctx, domain.ID, "sent", 2000); err != nil {
		t.Fatalf("increment sent 2: %v", err)
	}
	if err := repo.Increment(ctx, domain.ID, "bounced", 0); err != nil {
		t.Fatalf("increment bounced: %v", err)
	}

	// Unknown field should error.
	if err := repo.Increment(ctx, domain.ID, "bogus", 0); err == nil {
		t.Error("Increment with unknown field should error")
	}

	from := time.Now().UTC().Add(-2 * time.Hour)
	to := time.Now().UTC().Add(1 * time.Hour)

	hourly, err := repo.GetHourly(ctx, domain.ID, from, to)
	if err != nil {
		t.Fatalf("GetHourly: %v", err)
	}
	if len(hourly) != 1 {
		t.Fatalf("hourly len = %d, want 1 (same hour upserts)", len(hourly))
	}
	h := hourly[0]
	if h.Sent != 2 {
		t.Errorf("Sent = %d, want 2", h.Sent)
	}
	if h.Bounced != 1 {
		t.Errorf("Bounced = %d, want 1", h.Bounced)
	}
	if h.SizeBytesTotal != 3000 {
		t.Errorf("SizeBytesTotal = %d, want 3000", h.SizeBytesTotal)
	}

	agg, err := repo.GetAllDomainsAggregate(ctx, []string{domain.ID}, from, to)
	if err != nil {
		t.Fatalf("GetAllDomainsAggregate: %v", err)
	}
	if len(agg) != 1 {
		t.Fatalf("aggregate rows = %d, want 1", len(agg))
	}
	if agg[0].Sent != 2 || agg[0].Bounced != 1 {
		t.Errorf("aggregate = sent=%d bounced=%d, want 2/1", agg[0].Sent, agg[0].Bounced)
	}
}

// ---------- PasswordReset / RBLCheck ----------

func TestPasswordReset_Flow(t *testing.T) {
	ctx := context.Background()
	adminRepo := repository.NewAdminRepo(testPool)
	repo := repository.NewPasswordResetRepo(testPool)

	suffix := uniqueSuffix()
	admin, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        "pwreset-" + suffix + "@repo-test.com",
		PasswordHash: "$argon2id$v=19$m=65536,t=3,p=2$dGVzdHNhbHQ$dGVzdGhhc2g",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}
	defer adminRepo.Delete(ctx, admin.ID)

	hash := "sha256-" + suffix
	tok, err := repo.Create(ctx, admin.ID, hash, 1*time.Hour)
	if err != nil {
		t.Fatalf("create token: %v", err)
	}
	if tok.ID == "" {
		t.Error("token ID should be set")
	}

	found, err := repo.FindByHash(ctx, hash)
	if err != nil || found == nil {
		t.Fatalf("FindByHash: %v", err)
	}
	if found.AdminID != admin.ID {
		t.Errorf("AdminID = %q, want %q", found.AdminID, admin.ID)
	}
	if found.UsedAt != nil {
		t.Error("new token should not be used")
	}

	if err := repo.MarkUsed(ctx, found.ID); err != nil {
		t.Fatalf("mark used: %v", err)
	}

	// FindByHash filters out used/expired tokens — a used token must not come
	// back. That's the security guarantee callers rely on.
	afterMark, err := repo.FindByHash(ctx, hash)
	if err != nil {
		t.Fatalf("FindByHash post-mark: %v", err)
	}
	if afterMark != nil {
		t.Error("FindByHash should return nil for a used token")
	}

	// Issue a fresh token, then invalidate — InvalidateForAdmin must also
	// hide it from FindByHash.
	hash2 := "sha256b-" + suffix
	if _, err := repo.Create(ctx, admin.ID, hash2, 1*time.Hour); err != nil {
		t.Fatalf("create token 2: %v", err)
	}
	if err := repo.InvalidateForAdmin(ctx, admin.ID); err != nil {
		t.Fatalf("invalidate: %v", err)
	}
	afterInv, err := repo.FindByHash(ctx, hash2)
	if err != nil {
		t.Fatalf("FindByHash post-invalidate: %v", err)
	}
	if afterInv != nil {
		t.Error("FindByHash should return nil for a token invalidated via InvalidateForAdmin")
	}

	// CleanExpired should be safe to call even when nothing is expired.
	if _, err := repo.CleanExpired(ctx); err != nil {
		t.Fatalf("clean expired: %v", err)
	}
}

func TestRBLCheck_CRUD(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewRBLCheckRepo(testPool)

	// Unique IP range per run.
	ip := fmt.Sprintf("10.253.%d.%d", time.Now().Unix()%250, os.Getpid()%250)

	response := "127.0.0.2"
	id1, err := repo.Create(ctx, ip, "zen.spamhaus.org", true, &response)
	if err != nil || id1 == "" {
		t.Fatalf("create listed: %v", err)
	}
	id2, err := repo.Create(ctx, ip, "b.barracudacentral.org", false, nil)
	if err != nil || id2 == "" {
		t.Fatalf("create unlisted: %v", err)
	}

	latest, err := repo.GetLatestByIP(ctx, ip)
	if err != nil {
		t.Fatalf("GetLatestByIP: %v", err)
	}
	if len(latest) < 2 {
		t.Errorf("latest by IP rows = %d, want >=2", len(latest))
	}
	var sawListed, sawUnlisted bool
	for _, r := range latest {
		if r.RBLName == "zen.spamhaus.org" && r.Listed {
			sawListed = true
		}
		if r.RBLName == "b.barracudacentral.org" && !r.Listed {
			sawUnlisted = true
		}
	}
	if !sawListed || !sawUnlisted {
		t.Errorf("expected both rows represented: sawListed=%v sawUnlisted=%v", sawListed, sawUnlisted)
	}

	listed, err := repo.GetListedIPs(ctx)
	if err != nil {
		t.Fatalf("GetListedIPs: %v", err)
	}
	// ip_address::text in the underlying query returns the inet in CIDR form
	// ("10.253.1.1/32") — match on prefix rather than exact equality.
	foundListed := false
	for _, r := range listed {
		stripped := r.IPAddress
		if idx := strings.IndexByte(stripped, '/'); idx >= 0 {
			stripped = stripped[:idx]
		}
		if stripped == ip && r.Listed {
			foundListed = true
		}
	}
	if !foundListed {
		t.Errorf("our listed IP %q not in GetListedIPs (rows=%d)", ip, len(listed))
	}

	// Prune in the future — both rows are older than (now + 1m).
	deleted, err := repo.PruneOlderThan(ctx, -1*time.Minute)
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if deleted < 2 {
		t.Errorf("pruned %d rows, want >=2", deleted)
	}
}

// TestDovecotAuthToken_RevokeByTarget covers the purpose-scoped bulk revoke used
// by admin impersonation: it clears all impersonation tokens for one mailbox
// while leaving the importer's "import"-purpose tokens (and other users' tokens)
// intact, and is idempotent on a second call.
func TestDovecotAuthToken_RevokeByTarget(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewDovecotAuthTokenRepo(testPool)
	suffix := uniqueSuffix()
	target := "imp-" + suffix + "@repo-test.com"
	other := "other-" + suffix + "@repo-test.com"

	mustMint := func(user, purpose string) *repository.MintedToken {
		tok, err := repo.Mint(ctx, user, purpose, time.Hour)
		if err != nil {
			t.Fatalf("Mint(%s,%s): %v", user, purpose, err)
		}
		return tok
	}
	exists := func(id string) bool {
		var n int
		if err := testPool.QueryRow(ctx,
			`SELECT count(*) FROM dovecot_auth_tokens WHERE id = $1`, id).Scan(&n); err != nil {
			t.Fatalf("exists(%s): %v", id, err)
		}
		return n == 1
	}

	imp1 := mustMint(target, "impersonate")
	imp2 := mustMint(target, "impersonate")
	importTok := mustMint(target, "import")    // same mailbox, different consumer
	otherTok := mustMint(other, "impersonate") // different mailbox
	t.Cleanup(func() {
		_ = repo.Revoke(ctx, importTok.ID)
		_ = repo.Revoke(ctx, otherTok.ID)
	})

	n, err := repo.RevokeByTarget(ctx, target, "impersonate")
	if err != nil {
		t.Fatalf("RevokeByTarget: %v", err)
	}
	if n != 2 {
		t.Errorf("revoked %d rows, want 2", n)
	}
	if exists(imp1.ID) || exists(imp2.ID) {
		t.Error("impersonation tokens for target should be gone")
	}
	if !exists(importTok.ID) {
		t.Error("import-purpose token for the same mailbox must survive purpose-scoped revoke")
	}
	if !exists(otherTok.ID) {
		t.Error("another mailbox's impersonation token must survive")
	}

	// Idempotent: nothing left to revoke.
	again, err := repo.RevokeByTarget(ctx, target, "impersonate")
	if err != nil {
		t.Fatalf("RevokeByTarget (2nd): %v", err)
	}
	if again != 0 {
		t.Errorf("second revoke removed %d rows, want 0", again)
	}
}
