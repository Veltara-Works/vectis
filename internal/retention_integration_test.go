//go:build integration

package internal_test

// Integration test for the data-retention sweeper. Lives in the internal/
// package so CI's non-recursive `go test -tags integration ./internal/` runs it.
// Strategy: insert one old + one recent row in each PII table, run a sweep with
// a 90-day window, and assert the old row is purged while the recent one
// survives. Cutoffs are derived from real time (created_at far in the past vs
// now), so no clock injection is needed and unrelated fresh data is untouched.

import (
	"context"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/Veltara-Works/vectis/internal/retention"
	"github.com/Veltara-Works/vectis/internal/types"
)

func TestRetentionSweeper(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	domains := repository.NewDomainRepo(pool)
	dom, err := domains.Create(ctx, repository.DomainCreate{Name: "retention-test.example"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}
	// Use defer, not t.Cleanup: t.Cleanup runs after the test function returns,
	// by which point the deferred pool.Close() has already fired, so cleanup
	// would hit a closed pool and leak the domain (breaking the next run on the
	// unique name). This defer is registered after defer pool.Close(), so LIFO
	// runs it first — while the pool is still open.
	defer func() { _, _ = domains.Delete(context.Background(), dom.ID) }()

	old := time.Now().UTC().AddDate(0, 0, -200) // well past a 90-day window
	recent := time.Now().UTC().AddDate(0, 0, -1)

	// --- email_events: one old, one recent ---
	oldEvtID, recentEvtID := types.NewUUIDv7(), types.NewUUIDv7()
	for _, ev := range []struct {
		id string
		at time.Time
	}{{oldEvtID, old}, {recentEvtID, recent}} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO email_events (id, domain_id, message_id, event_type, created_at)
			 VALUES ($1, $2, $3, 'open', $4)`,
			ev.id, dom.ID, "<msg-"+ev.id+"@retention-test.example>", ev.at); err != nil {
			t.Fatalf("insert email_event: %v", err)
		}
	}

	// --- messages: one old, one recent ---
	oldMsgID, recentMsgID := types.NewUUIDv7(), types.NewUUIDv7()
	for _, m := range []struct {
		id string
		at time.Time
	}{{oldMsgID, old}, {recentMsgID, recent}} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO messages (id, domain_id, message_id, direction, sender, recipients, status, created_at)
			 VALUES ($1, $2, $3, 'inbound', 'sender@example.com', ARRAY['rcpt@retention-test.example'], 'received', $4)`,
			m.id, dom.ID, "<msg-"+m.id+"@retention-test.example>", m.at); err != nil {
			t.Fatalf("insert message: %v", err)
		}
	}

	sweeper := retention.NewSweeper(
		repository.NewEmailEventRepo(pool),
		repository.NewMessageRepo(pool),
		repository.NewAuditRepo(pool),
		retention.Config{TrackingEventDays: 90, MessageMetadataDays: 90, RunInterval: time.Hour},
		logger,
	)

	res := sweeper.RunOnce(ctx)
	if res.TrackingEvents < 1 || res.MessageMetadata < 1 {
		t.Fatalf("expected at least 1 purge per table, got %+v", res)
	}

	exists := func(table, id string) bool {
		var n int
		if err := pool.QueryRow(ctx, "SELECT count(*) FROM "+table+" WHERE id = $1", id).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		return n > 0
	}

	if exists("email_events", oldEvtID) {
		t.Error("old email_event should have been purged")
	}
	if !exists("email_events", recentEvtID) {
		t.Error("recent email_event should have been kept")
	}
	if exists("messages", oldMsgID) {
		t.Error("old message should have been purged")
	}
	if !exists("messages", recentMsgID) {
		t.Error("recent message should have been kept")
	}
}

func TestRetentionSweeper_DisabledKeepsEverything(t *testing.T) {
	// A zero-window config must not delete anything (Enabled() == false).
	s := retention.NewSweeper(nil, nil, nil,
		retention.Config{TrackingEventDays: 0, MessageMetadataDays: 0}, slog.New(slog.NewTextHandler(os.Stderr, nil)))
	if s.Enabled() {
		t.Fatal("sweeper with no windows must report disabled")
	}
	// RunOnce with both windows 0 touches no repos, so nil repos are safe.
	if res := s.RunOnce(context.Background()); res.TrackingEvents != 0 || res.MessageMetadata != 0 {
		t.Fatalf("disabled sweep must delete nothing, got %+v", res)
	}
}
