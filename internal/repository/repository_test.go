//go:build integration

package repository_test

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/repository"
)

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
	repo := repository.NewWebhookRepo(testPool)
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

	wh, err := repo.Create(ctx, repository.WebhookCreate{
		URL:       "https://example.com/hook/" + suffix,
		Secret:    "testsecret-" + suffix,
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

	hooks, err := repo.ListAll(ctx)
	if err != nil {
		t.Fatalf("list webhooks: %v", err)
	}
	found := false
	for _, h := range hooks {
		if h.ID == wh.ID {
			found = true
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

	if err := repo.Resolve(ctx, dedup); err != nil {
		t.Fatalf("resolve: %v", err)
	}

	// After resolve, FindRecent still returns the row but with ResolvedAt set.
	after, err := repo.FindRecent(ctx, dedup, 1*time.Hour)
	if err != nil || after == nil {
		t.Fatalf("find recent after resolve: %v, after=%v", err, after)
	}
	if after.ResolvedAt == nil {
		t.Error("ResolvedAt should be set after Resolve")
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
