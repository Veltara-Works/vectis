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
	s.validateFn = func(context.Context, string) error { return nil } // dummy files aren't real archives

	removed := s.pruneOlderThan(context.Background(), 30)
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
	s.validateFn = func(context.Context, string) error { return nil } // dummy files aren't real archives

	removed := s.pruneOlderThan(context.Background(), 30)
	if removed != 1 {
		t.Errorf("removed = %d, want 1 (newest kept)", removed)
	}
	// vectis-a (200d) is newest of the two, must remain.
	if _, err := os.Stat(filepath.Join(dir, "vectis-a.tar.gz.enc")); err != nil {
		t.Errorf("newest archive must be kept: %v", err)
	}
}

// TestSchedulerPruneProtectsRestoreChain is the core manifest-aware guard: an
// incremental's base full is OLDER than the cutoff, but must survive because a
// newer incremental depends on it. A standalone full that predates the chain
// (not a RestoreChain member) is still reaped. Without this, blind age-based
// prune deletes the base full and makes restore hard-fail its pre-flight.
func TestSchedulerPruneProtectsRestoreChain(t *testing.T) {
	dir := t.TempDir()
	cfg := DefaultConfig()
	cfg.BackupDir = dir
	mgr := NewManager(nil, quietLogger(), cfg)

	now := time.Date(2026, 5, 30, 0, 0, 0, 0, time.UTC)
	// name -> (ageDays, type, id, parentID)
	base := filepath.Join(dir, "vectis-base.tar.gz.enc")             // chain base full, 40d (older than 30d cutoff)
	incr := filepath.Join(dir, "vectis-incr-new.tar.gz.enc")         // incremental on base, 5d (newest)
	standalone := filepath.Join(dir, "vectis-standalone.tar.gz.enc") // pre-chain full, 100d (prunable)
	writeAged := func(path string, ageDays int) {
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		mod := now.Add(-time.Duration(ageDays) * 24 * time.Hour)
		if err := os.Chtimes(path, mod, mod); err != nil {
			t.Fatal(err)
		}
	}
	writeAged(standalone, 100)
	writeAged(base, 40)
	writeAged(incr, 5)

	// Manifest order matters: LastFull walks backwards, so `base` (the later of
	// the two fulls) is the chain base. RestoreChain = {base, incr}.
	manifest, _ := LoadManifest(dir)
	if err := manifest.Add(ManifestEntry{ID: "standalone", Type: BackupFull, Path: standalone, CreatedAt: now.Add(-100 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Add(ManifestEntry{ID: "base", Type: BackupFull, Path: base, CreatedAt: now.Add(-40 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Add(ManifestEntry{ID: "incr", Type: BackupIncremental, ParentID: "base", Path: incr, CreatedAt: now.Add(-5 * 24 * time.Hour)}); err != nil {
		t.Fatal(err)
	}

	s, _ := NewScheduler(mgr, SchedulerConfig{Schedule: "0 2 * * *", RetainDays: 30}, quietLogger())
	s.now = func() time.Time { return now }
	s.validateFn = func(context.Context, string) error { return nil } // dummy files aren't real archives

	removed := s.pruneOlderThan(context.Background(), 30)
	if removed != 1 {
		t.Errorf("removed = %d, want 1 (only the pre-chain standalone full)", removed)
	}
	// The chain base full must survive despite being older than the cutoff.
	if _, err := os.Stat(base); err != nil {
		t.Errorf("RestoreChain base full must be protected from prune: %v", err)
	}
	if _, err := os.Stat(incr); err != nil {
		t.Errorf("newest incremental must be kept: %v", err)
	}
	// The standalone pre-chain full is not a chain member and is older than the
	// cutoff, so it is correctly reaped.
	if _, err := os.Stat(standalone); !os.IsNotExist(err) {
		t.Errorf("pre-chain standalone full should have been pruned; stat err = %v", err)
	}
	// Manifest reconciled: the standalone entry is dropped, chain intact.
	reloaded, _ := LoadManifest(dir)
	if reloaded.LastFull() == nil || reloaded.LastFull().ID != "base" {
		t.Errorf("manifest LastFull after prune = %v, want base", reloaded.LastFull())
	}
	if len(reloaded.Entries) != 2 {
		t.Errorf("manifest entries after prune = %d, want 2 (base+incr)", len(reloaded.Entries))
	}
}

// TestSweepOrphanTemp verifies the startup sweep removes only OUR orphaned temp
// working dirs (in TMPDIR) and *.tmp sidecars (in BackupDir), leaving unrelated
// dirs, stray files, and real archives untouched.
func TestSweepOrphanTemp(t *testing.T) {
	tmpParent := t.TempDir()
	t.Setenv("TMPDIR", tmpParent) // os.TempDir() honours $TMPDIR on unix
	backupDir := t.TempDir()

	// Orphaned working dirs (all five worker prefixes).
	orphanDirs := []string{
		"vectis-backup-123", "vectis-backup-incr-9", "vectis-incr-apply-4",
		"vectis-restore-7", "vectis-restore-keep-1",
	}
	for _, n := range orphanDirs {
		if err := os.MkdirAll(filepath.Join(tmpParent, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// Must survive: unrelated dir, and a stray file that happens to match a prefix
	// (we only remove DIRS in /tmp).
	if err := os.MkdirAll(filepath.Join(tmpParent, "unrelated-dir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tmpParent, "vectis-backup-stray-file"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Orphaned .tmp sidecars in the backup dir, plus a real archive that must stay.
	for _, n := range []string{"vectis-20260101-000000.tar.gz.enc.tmp", "manifest.json.tmp"} {
		if err := os.WriteFile(filepath.Join(backupDir, n), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	realArchive := filepath.Join(backupDir, "vectis-20260101-000000.tar.gz.enc")
	if err := os.WriteFile(realArchive, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := DefaultConfig()
	cfg.BackupDir = backupDir
	mgr := NewManager(nil, quietLogger(), cfg)

	n := mgr.SweepOrphanTemp()
	if n != 7 { // 5 dirs + 2 .tmp files
		t.Errorf("SweepOrphanTemp removed %d, want 7", n)
	}
	for _, name := range orphanDirs {
		if _, err := os.Stat(filepath.Join(tmpParent, name)); !os.IsNotExist(err) {
			t.Errorf("orphan dir %s should be swept; stat err = %v", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(tmpParent, "unrelated-dir")); err != nil {
		t.Errorf("unrelated dir must survive: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmpParent, "vectis-backup-stray-file")); err != nil {
		t.Errorf("stray file (not a dir) must survive: %v", err)
	}
	if _, err := os.Stat(realArchive); err != nil {
		t.Errorf("real archive must survive: %v", err)
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
