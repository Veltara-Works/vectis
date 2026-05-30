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
	RetainDays int    // archives older than this are pruned after each run; 0 = keep all
}

// Scheduler runs full backups on a cron schedule and prunes old archives.
// It follows the same Start/Stop pattern as audit.Pruner. The scheduler only
// creates FULL backups, so retention never orphans an incremental chain.
type Scheduler struct {
	mgr    *Manager
	sched  cron.Schedule
	cfg    SchedulerConfig
	logger *slog.Logger
	stopCh chan struct{}
	now    func() time.Time // injectable for tests
}

// NewScheduler parses the cron schedule and returns a ready scheduler. It
// returns an error if the schedule is empty or invalid, so a misconfiguration
// surfaces at startup rather than silently never running.
func NewScheduler(mgr *Manager, cfg SchedulerConfig, logger *slog.Logger) (*Scheduler, error) {
	if strings.TrimSpace(cfg.Schedule) == "" {
		return nil, fmt.Errorf("backup schedule is empty")
	}
	parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
	sched, err := parser.Parse(cfg.Schedule)
	if err != nil {
		return nil, fmt.Errorf("parse backup schedule %q: %w", cfg.Schedule, err)
	}
	return &Scheduler{
		mgr:    mgr,
		sched:  sched,
		cfg:    cfg,
		logger: logger,
		stopCh: make(chan struct{}),
		now:    time.Now,
	}, nil
}

// Start launches the scheduling loop in a background goroutine.
func (s *Scheduler) Start() {
	s.logger.Info("starting backup scheduler",
		"schedule", s.cfg.Schedule, "retain_days", s.cfg.RetainDays)
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
	by := "scheduler"
	s.logger.Info("scheduled backup starting")
	path, size, err := s.mgr.Create(ctx, &by)
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
