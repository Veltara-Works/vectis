package backup

import (
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewScheduler(t *testing.T) {
	mgr := NewManager(nil, quietLogger(), DefaultConfig())

	t.Run("valid schedule parses", func(t *testing.T) {
		s, err := NewScheduler(mgr, SchedulerConfig{Schedule: "0 2 * * *", RetainDays: 30}, quietLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// 5-field cron, daily at 02:00.
		from := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)
		next := s.sched.Next(from)
		want := time.Date(2026, 5, 31, 2, 0, 0, 0, time.UTC)
		if !next.Equal(want) {
			t.Errorf("Next(%v) = %v, want %v", from, next, want)
		}
	})

	t.Run("empty schedule rejected", func(t *testing.T) {
		if _, err := NewScheduler(mgr, SchedulerConfig{Schedule: "   "}, quietLogger()); err == nil {
			t.Error("expected error for empty schedule")
		}
	})

	t.Run("invalid schedule rejected", func(t *testing.T) {
		if _, err := NewScheduler(mgr, SchedulerConfig{Schedule: "not a cron"}, quietLogger()); err == nil {
			t.Error("expected error for invalid schedule")
		}
	})
}

// TestSchedulerRunOnceUsesNilActor guards the v0.1.19 regression where scheduled
// backups passed the sentinel string "scheduler" as the actor. backup_jobs
// .triggered_by is a UUID FK to admins(id), so a non-UUID value fails the insert
// ("invalid input syntax for type uuid") and silently kills every scheduled
// backup. A system-triggered backup has no admin actor → triggered_by must be nil.
func TestSchedulerRunOnceUsesNilActor(t *testing.T) {
	mgr := NewManager(nil, quietLogger(), DefaultConfig())
	s, err := NewScheduler(mgr, SchedulerConfig{Schedule: "0 2 * * *", RetainDays: 0}, quietLogger())
	if err != nil {
		t.Fatalf("NewScheduler: %v", err)
	}

	called := false
	sentinel := "set-by-test" // non-nil so "never called" is distinguishable from "passed nil"
	gotTriggeredBy := &sentinel
	s.createFn = func(_ context.Context, triggeredBy *string) (string, int64, error) {
		called = true
		gotTriggeredBy = triggeredBy
		return "/var/vectis/backups/vectis-test.tar.gz.enc", 123, nil
	}

	s.RunOnce(context.Background())

	if !called {
		t.Fatal("RunOnce did not invoke the backup create function")
	}
	if gotTriggeredBy != nil {
		t.Errorf("scheduled backup triggered_by = %q, want nil (NULL) — a non-UUID actor breaks the uuid insert", *gotTriggeredBy)
	}
}

func TestSchedulerPruneOlderThan(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.BackupDir = dir
	mgr := NewManager(nil, quietLogger(), cfg)

	now := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	// name -> age in days. The newest must be kept regardless of cutoff.
	files := map[string]int{
		"vectis-newest.tar.gz.enc": 0,
		"vectis-recent.tar.gz.enc": 5,
		"vectis-old1.tar.gz.enc":   40,
		"vectis-old2.tar.gz":       100,
		"not-a-backup.txt":         100, // must be ignored
	}
	for name, ageDays := range files {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		mod := now.Add(-time.Duration(ageDays) * 24 * time.Hour)
		if err := os.Chtimes(p, mod, mod); err != nil {
			t.Fatal(err)
		}
	}

	s, err := NewScheduler(mgr, SchedulerConfig{Schedule: "0 2 * * *", RetainDays: 30}, quietLogger())
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return now }

	removed := s.pruneOlderThan(30)
	if removed != 2 {
		t.Errorf("removed = %d, want 2 (old1, old2)", removed)
	}

	mustExist := []string{"vectis-newest.tar.gz.enc", "vectis-recent.tar.gz.enc", "not-a-backup.txt"}
	for _, n := range mustExist {
		if _, err := os.Stat(filepath.Join(dir, n)); err != nil {
			t.Errorf("%s should have been kept: %v", n, err)
		}
	}
	mustGone := []string{"vectis-old1.tar.gz.enc", "vectis-old2.tar.gz"}
	for _, n := range mustGone {
		if _, err := os.Stat(filepath.Join(dir, n)); !os.IsNotExist(err) {
			t.Errorf("%s should have been pruned; stat err = %v", n, err)
		}
	}
}

// Even when everything is older than the cutoff, the most recent archive is
// never deleted — there must always be at least one restorable backup.
func TestSchedulerPruneKeepsNewest(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.BackupDir = dir
	mgr := NewManager(nil, quietLogger(), cfg)

	now := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	for name, ageDays := range map[string]int{
		"vectis-a.tar.gz.enc": 200,
		"vectis-b.tar.gz.enc": 300,
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		mod := now.Add(-time.Duration(ageDays) * 24 * time.Hour)
		_ = os.Chtimes(p, mod, mod)
	}

	s, _ := NewScheduler(mgr, SchedulerConfig{Schedule: "0 2 * * *", RetainDays: 30}, quietLogger())
	s.now = func() time.Time { return now }

	removed := s.pruneOlderThan(30)
	if removed != 1 {
		t.Errorf("removed = %d, want 1 (newest kept)", removed)
	}
	// vectis-a (200d) is newest of the two, must remain.
	if _, err := os.Stat(filepath.Join(dir, "vectis-a.tar.gz.enc")); err != nil {
		t.Errorf("newest archive must be kept: %v", err)
	}
}

// TestExpectedInterval verifies the max-gap sampling used by the backup-age
// health check: a uniform daily cron yields ~24h, but a schedule with an uneven
// gap (weekday-only) must yield the widest gap (across the weekend), so the
// health check never false-alarms during the expected quiet stretch.
func TestExpectedInterval(t *testing.T) {
	from := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC) // a Monday

	t.Run("uniform daily is ~24h", func(t *testing.T) {
		got, err := ExpectedInterval("0 2 * * *", "", from, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 24*time.Hour {
			t.Errorf("ExpectedInterval(daily) = %v, want 24h", got)
		}
	})

	t.Run("weekday-only spans the weekend", func(t *testing.T) {
		// Fires 02:00 Mon-Fri. The largest consecutive gap is Fri 02:00 -> Mon
		// 02:00 = 72h. Sampling from Monday noon, 8 samples covers >1 week.
		got, err := ExpectedInterval("0 2 * * 1-5", "", from, 8)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 72*time.Hour {
			t.Errorf("ExpectedInterval(weekday-only) = %v, want 72h", got)
		}
	})

	t.Run("timezone honoured", func(t *testing.T) {
		// Daily in Sydney is still a 24h interval regardless of tz.
		got, err := ExpectedInterval("0 2 * * *", "Australia/Sydney", from, 4)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 24*time.Hour {
			t.Errorf("ExpectedInterval(sydney daily) = %v, want 24h", got)
		}
	})

	t.Run("samples clamped to >=2", func(t *testing.T) {
		got, err := ExpectedInterval("0 2 * * *", "", from, 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != 24*time.Hour {
			t.Errorf("ExpectedInterval(samples=0 clamped) = %v, want 24h", got)
		}
	})

	t.Run("invalid schedule errors", func(t *testing.T) {
		if _, err := ExpectedInterval("nope", "", from, 4); err == nil {
			t.Error("expected error for invalid schedule")
		}
	})
}
