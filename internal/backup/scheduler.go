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

// Scheduler runs full backups on a cron schedule and prunes old archives.
// It follows the same Start/Stop pattern as audit.Pruner. The scheduler only
// creates FULL backups, so retention never orphans an incremental chain.
type Scheduler struct {
	mgr      *Manager
	sched    cron.Schedule
	cfg      SchedulerConfig
	logger   *slog.Logger
	stopCh   chan struct{}
	now      func() time.Time                                                      // injectable for tests
	createFn func(ctx context.Context, triggeredBy *string) (string, int64, error) // injectable for tests
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
		mgr:      mgr,
		sched:    sched,
		cfg:      cfg,
		logger:   logger,
		stopCh:   make(chan struct{}),
		now:      time.Now,
		createFn: mgr.Create,
	}, nil
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
		return
	}
	s.logger.Info("scheduled backup complete", "path", path, "size_bytes", size)

	if s.cfg.RetainDays > 0 {
		if n := s.pruneOlderThan(s.cfg.RetainDays); n > 0 {
			s.logger.Info("pruned old backups", "removed", n, "retain_days", s.cfg.RetainDays)
		}
	}
}

// pruneOlderThan deletes backup archives older than retainDays from the backup
// dir, always keeping the most recent archive so there is never zero backups.
// Returns the number removed. The scheduler creates only full backups, so this
// never breaks an incremental chain.
func (s *Scheduler) pruneOlderThan(retainDays int) int {
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

	// Newest first; never delete archives[0].
	sort.Slice(archives, func(i, j int) bool { return archives[i].mod.After(archives[j].mod) })

	cutoff := s.now().Add(-time.Duration(retainDays) * 24 * time.Hour)
	removed := 0
	for i, a := range archives {
		if i == 0 {
			continue // always keep the most recent
		}
		if a.mod.Before(cutoff) {
			if err := os.Remove(a.path); err != nil {
				s.logger.Error("prune: remove archive", "path", a.path, "error", err)
				continue
			}
			removed++
		}
	}
	return removed
}
