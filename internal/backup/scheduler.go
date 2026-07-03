package backup

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/robfig/cron/v3"
)

// SchedulerConfig controls the periodic backup scheduler.
type SchedulerConfig struct {
	Schedule   string // standard 5-field cron, e.g. "0 2 * * *"; empty = disabled
	Timezone   string // IANA tz (e.g. "Australia/Sydney") evaluated via CRON_TZ; empty = UTC/container-local
	RetainDays int    // archives older than this are pruned after each run; 0 = keep all
}

// cronParser is the standard 5-field parser shared by NewScheduler and
// NextScheduledRun. It also accepts a leading CRON_TZ= prefix, which is how
// a configured timezone is honoured.
var cronParser = cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)

// buildCronSchedule parses a 5-field cron expression, evaluating it in the
// given IANA timezone when one is set (empty = the container's local time,
// which is UTC in our images). The timezone is validated up front so a bad
// value surfaces as a clear error instead of silently falling back to UTC.
func buildCronSchedule(schedule, timezone string) (cron.Schedule, error) {
	spec := strings.TrimSpace(schedule)
	if spec == "" {
		return nil, fmt.Errorf("backup schedule is empty")
	}
	if tz := strings.TrimSpace(timezone); tz != "" {
		if _, err := time.LoadLocation(tz); err != nil {
			return nil, fmt.Errorf("invalid backup timezone %q: %w", tz, err)
		}
		spec = "CRON_TZ=" + tz + " " + spec
	}
	sched, err := cronParser.Parse(spec)
	if err != nil {
		return nil, fmt.Errorf("parse backup schedule %q: %w", schedule, err)
	}
	return sched, nil
}

// NextScheduledRun returns the next time the given schedule would fire after
// `from`, honouring the timezone. Used by the API to show operators the next
// backup time without needing a live scheduler instance.
func NextScheduledRun(schedule, timezone string, from time.Time) (time.Time, error) {
	sched, err := buildCronSchedule(schedule, timezone)
	if err != nil {
		return time.Time{}, err
	}
	return sched.Next(from), nil
}

// StaleGraceFactor multiplies the expected backup interval to yield the age at
// which a backup is considered stale, so a single slightly-late run does not
// flap the health signal. 1.5x means a daily backup flags at ~36h. Single source
// of truth for both the health monitor and the settings endpoint. (Locked with
// Ian 2026-07-03.)
const StaleGraceFactor = 1.5

// ExpectedInterval returns the largest gap between consecutive fires of the
// schedule, sampled over the next `samples` runs starting from `from`. This is
// the longest a healthy install should ever go between backups: for a uniform
// daily cron it is ~24h, but for schedules with uneven gaps (e.g. weekday-only)
// it is the widest gap (the weekend), so a health check built on it does not
// false-alarm across the expected quiet stretch. samples < 2 is clamped to 2.
func ExpectedInterval(schedule, timezone string, from time.Time, samples int) (time.Duration, error) {
	sched, err := buildCronSchedule(schedule, timezone)
	if err != nil {
		return 0, err
	}
	if samples < 2 {
		samples = 2
	}
	var maxGap time.Duration
	t := from
	for i := 0; i < samples; i++ {
		next := sched.Next(t)
		if gap := next.Sub(t); gap > maxGap {
			maxGap = gap
		}
		t = next
	}
	return maxGap, nil
}

// Scheduler runs full backups on a cron schedule and prunes old archives.
// It follows the same Start/Stop pattern as audit.Pruner. The scheduler itself
// only creates FULL backups, but the same backup dir also holds UI-created
// incrementals, so prune is manifest-aware and never reaps a RestoreChain member
// (see pruneOlderThan).
type Scheduler struct {
	mgr        *Manager
	sched      cron.Schedule
	cfg        SchedulerConfig
	logger     *slog.Logger
	stopCh     chan struct{}
	now        func() time.Time                                                      // injectable for tests
	createFn   func(ctx context.Context, triggeredBy *string) (string, int64, error) // injectable for tests
	validateFn func(ctx context.Context, path string) error                          // injectable for tests; validates an archive before prune reaps older ones
	onError    func(ctx context.Context, err error)                                  // optional: called when a scheduled run FAILS (C-2 alerting)
	onSuccess  func(ctx context.Context)                                             // optional: called when a scheduled run SUCCEEDS (C-2 alert resolve)
}

// NewScheduler parses the cron schedule and returns a ready scheduler. It
// returns an error if the schedule is empty or invalid, so a misconfiguration
// surfaces at startup rather than silently never running.
func NewScheduler(mgr *Manager, cfg SchedulerConfig, logger *slog.Logger) (*Scheduler, error) {
	sched, err := buildCronSchedule(cfg.Schedule, cfg.Timezone)
	if err != nil {
		return nil, err
	}
	return &Scheduler{
		mgr:        mgr,
		sched:      sched,
		cfg:        cfg,
		logger:     logger,
		stopCh:     make(chan struct{}),
		now:        time.Now,
		createFn:   mgr.Create,
		validateFn: mgr.validateArchive,
	}, nil
}

// SetOnError registers a callback invoked when a scheduled backup run fails.
// It exists so the API layer can raise an alert (the scheduled path calls
// mgr.Create synchronously and never fires the manager's onComplete callback,
// so the completion-notification wiring is dead for nightly backups). Injected
// as a plain callback so this package never imports internal/monitor.
func (s *Scheduler) SetOnError(fn func(ctx context.Context, err error)) {
	s.onError = fn
}

// SetOnSuccess registers a callback invoked when a scheduled backup run
// succeeds. It lets the API layer RESOLVE the scheduled-failure alert raised by
// onError — the run-failure alert uses its own dedup key (not the health
// monitor's staleness key), so only a subsequent successful run clears it.
func (s *Scheduler) SetOnSuccess(fn func(ctx context.Context)) {
	s.onSuccess = fn
}

// Start launches the scheduling loop in a background goroutine.
func (s *Scheduler) Start() {
	s.logger.Info("starting backup scheduler",
		"schedule", s.cfg.Schedule, "timezone", s.cfg.Timezone, "retain_days", s.cfg.RetainDays)
	go s.loop()
}

// Stop signals the scheduling loop to stop.
func (s *Scheduler) Stop() {
	s.logger.Info("stopping backup scheduler")
	close(s.stopCh)
}

func (s *Scheduler) loop() {
	for {
		now := s.now()
		next := s.sched.Next(now)
		wait := next.Sub(now)
		s.logger.Info("backup scheduler: next run",
			"at", next.Format(time.RFC3339), "in", wait.String())

		timer := time.NewTimer(wait)
		select {
		case <-s.stopCh:
			timer.Stop()
			return
		case <-timer.C:
			s.RunOnce(context.Background())
		}
	}
}

// RunOnce creates one full backup and applies retention. Exposed for manual
// triggering and tests.
func (s *Scheduler) RunOnce(ctx context.Context) {
	// System-triggered backups have no admin actor. backup_jobs.triggered_by is
	// a UUID FK to admins(id); passing a sentinel string ("scheduler") fails the
	// insert with "invalid input syntax for type uuid" and silently kills every
	// scheduled backup. nil records NULL — the proven contract manual backups and
	// the pre-regression scheduler both used.
	s.logger.Info("scheduled backup starting")
	path, size, err := s.createFn(ctx, nil)
	if err != nil {
		s.logger.Error("scheduled backup failed", "error", err)
		if s.onError != nil {
			s.onError(ctx, err)
		}
		return
	}
	s.logger.Info("scheduled backup complete", "path", path, "size_bytes", size)
	if s.onSuccess != nil {
		s.onSuccess(ctx) // clears any prior scheduled-failure alert
	}

	if s.cfg.RetainDays > 0 {
		if n := s.pruneOlderThan(ctx, s.cfg.RetainDays); n > 0 {
			s.logger.Info("pruned old backups", "removed", n, "retain_days", s.cfg.RetainDays)
		}
	}
}

// pruneOlderThan deletes backup archives older than retainDays from the backup
// dir. It is manifest-aware: it NEVER deletes a member of the current
// RestoreChain (the latest full plus its incrementals), regardless of age — an
// incremental's base full is by definition older than the incrementals that
// depend on it, so blind age-based pruning targets exactly the wrong file and a
// missing base makes restore hard-fail its pre-flight (unrecoverable). It also
// always keeps the single newest archive (never zero backups), validates the
// survivors before reaping older ones (never delete good older backups to keep a
// corrupt newest one), and reconciles the manifest with disk afterward. Returns
// the number removed. Fails CLOSED: if the manifest can't be loaded, chain
// membership is unknown, so it deletes nothing.
func (s *Scheduler) pruneOlderThan(ctx context.Context, retainDays int) int {
	// Fail closed on a missing/corrupt manifest: without it we can't know which
	// archives are chain members. LoadManifest returns an empty (non-nil)
	// manifest when the file simply doesn't exist (legacy installs), which is a
	// valid "no chain" state, not an error.
	manifest, err := LoadManifest(s.mgr.cfg.BackupDir)
	if err != nil {
		s.logger.Error("prune: load manifest — skipping prune (fail-closed)", "error", err)
		return 0
	}
	chain := manifest.RestoreChain()
	protected := make(map[string]bool, len(chain))
	for _, e := range chain {
		protected[filepath.Base(e.Path)] = true
	}

	entries, err := os.ReadDir(s.mgr.cfg.BackupDir)
	if err != nil {
		s.logger.Error("prune: read backup dir", "error", err)
		return 0
	}

	type arch struct {
		path string
		mod  time.Time
	}
	var archives []arch
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".tar.gz") && !strings.HasSuffix(name, ".tar.gz.enc") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		archives = append(archives, arch{filepath.Join(s.mgr.cfg.BackupDir, name), info.ModTime()})
	}
	if len(archives) == 0 {
		return 0
	}

	// Newest first; index 0 is always kept.
	sort.Slice(archives, func(i, j int) bool { return archives[i].mod.After(archives[j].mod) })

	// Clamp defensively: retainDays can arrive straight from the DB (bypassing
	// Settings.Validate), and an unbounded value overflows the duration below,
	// flipping the cutoff into the future and deleting all-but-newest.
	if retainDays > MaxRetainDays {
		retainDays = MaxRetainDays
	}
	cutoff := s.now().Add(-time.Duration(retainDays) * 24 * time.Hour)

	// Determine deletion candidates first: never the newest, never a chain
	// member, only those older than the cutoff. Computing this up front lets us
	// skip the (potentially expensive) survivor validation on nights where
	// nothing is eligible anyway.
	var candidates []string
	for i, a := range archives {
		if i == 0 {
			continue // always keep the most recent
		}
		if protected[filepath.Base(a.path)] {
			continue // never delete a RestoreChain member, regardless of age
		}
		if a.mod.Before(cutoff) {
			candidates = append(candidates, a.path)
		}
	}
	if len(candidates) == 0 {
		return 0
	}

	// Validate the survivors before reaping older backups: this protects the
	// invariant "never delete good older backups to keep a corrupt newest one".
	// Validate the whole current RestoreChain (base full + any incrementals); if
	// there is no chain (a legacy install with no manifest), validate the single
	// newest archive we are keeping. This is O(1) in the nightly path — prune
	// runs only from RunOnce, right after the scheduler wrote a fresh FULL, so
	// the chain is just [that full] — while staying correct if a UI incremental
	// has raced into the chain (a corrupt incremental then correctly pauses
	// retention rather than letting us delete older good fulls).
	survivors := make([]string, 0, len(chain)+1)
	for _, e := range chain {
		survivors = append(survivors, e.Path)
	}
	if len(survivors) == 0 {
		survivors = append(survivors, archives[0].path)
	}
	for _, p := range survivors {
		if err := s.validateFn(ctx, p); err != nil {
			// Loud + operator-visible: retention is intentionally paused (not a
			// silent no-op) so a corrupt/undecryptable survivor doesn't cause us
			// to delete good older backups — and so the operator can see why the
			// dir stops shrinking (e.g. the encryption key was cleared).
			s.logger.Warn("prune: survivor archive failed validation — retention PAUSED, older backups kept",
				"path", p, "error", err)
			return 0
		}
	}

	removed := 0
	for _, p := range candidates {
		if err := os.Remove(p); err != nil {
			s.logger.Error("prune: remove archive", "path", p, "error", err)
			continue
		}
		removed++
	}

	// Reconcile the manifest with disk (drop entries for the files we removed and
	// any now-orphaned incrementals). Done via the Manager under manifestMu with
	// a FRESH load, so it can't clobber an entry a concurrent UI backup added
	// while this prune ran.
	if removed > 0 {
		s.mgr.reconcileManifest()
	}

	return removed
}
