// Package retention provides a background sweeper that purges PII-bearing
// records past their retention window. It deliberately does NOT touch the audit
// trail — audit-log retention is owned by the audit pruner (internal/audit).
// This sweeper owns the data that grows unbounded and carries personal data:
// engagement tracking events (IP + user-agent) and message metadata.
package retention

import (
	"context"
	"log/slog"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// Config holds the sweeper's tuning knobs. Each *Days value is 0 = keep forever.
type Config struct {
	TrackingEventDays   int           // purge email_events older than this; 0 = keep
	MessageMetadataDays int           // purge messages metadata older than this; 0 = keep
	RunInterval         time.Duration // how often to sweep; default 24h
}

// DefaultConfig returns sensible defaults: keep engagement events ~90 days,
// keep message metadata indefinitely (operationally useful; opt in to purge).
func DefaultConfig() Config {
	return Config{
		TrackingEventDays:   90,
		MessageMetadataDays: 0,
		RunInterval:         24 * time.Hour,
	}
}

// Result reports what a single sweep deleted.
type Result struct {
	TrackingEvents  int64
	MessageMetadata int64
}

// Sweeper periodically purges records past their retention window. It follows
// the same Start/Stop pattern as audit.Pruner.
type Sweeper struct {
	events   *repository.EmailEventRepo
	messages *repository.MessageRepo
	audit    *repository.AuditRepo
	cfg      Config
	logger   *slog.Logger
	stopCh   chan struct{}
	now      func() time.Time // injectable for tests
}

// NewSweeper builds a sweeper. audit may be nil (the sweep still runs; it just
// won't record a summary entry).
func NewSweeper(events *repository.EmailEventRepo, messages *repository.MessageRepo,
	audit *repository.AuditRepo, cfg Config, logger *slog.Logger) *Sweeper {
	if cfg.RunInterval <= 0 {
		cfg.RunInterval = 24 * time.Hour
	}
	return &Sweeper{
		events:   events,
		messages: messages,
		audit:    audit,
		cfg:      cfg,
		logger:   logger,
		stopCh:   make(chan struct{}),
		now:      time.Now,
	}
}

// Enabled reports whether any retention window is configured.
func (s *Sweeper) Enabled() bool {
	return s.cfg.TrackingEventDays > 0 || s.cfg.MessageMetadataDays > 0
}

// Start launches the sweep loop in a background goroutine. It is a no-op when
// no retention window is set, so an unconfigured install never deletes data.
func (s *Sweeper) Start() {
	if !s.Enabled() {
		s.logger.Info("retention sweeper disabled (no retention windows set)")
		return
	}
	s.logger.Info("starting retention sweeper",
		"tracking_event_days", s.cfg.TrackingEventDays,
		"message_metadata_days", s.cfg.MessageMetadataDays,
		"interval", s.cfg.RunInterval)
	go s.loop()
}

// Stop signals the sweep loop to stop. Safe to call even if Start short-
// circuited (disabled) or Stop was already called.
func (s *Sweeper) Stop() {
	select {
	case <-s.stopCh:
	default:
		close(s.stopCh)
	}
}

// RunOnce executes a single sweep. Each window is purged independently; an
// error on one does not abort the other. Exposed for manual triggering + tests.
func (s *Sweeper) RunOnce(ctx context.Context) Result {
	var res Result
	now := s.now().UTC()

	if s.cfg.TrackingEventDays > 0 {
		cutoff := now.AddDate(0, 0, -s.cfg.TrackingEventDays)
		if n, err := s.events.DeleteOlderThan(ctx, cutoff); err != nil {
			s.logger.Error("retention: purge tracking events", "error", err)
		} else {
			res.TrackingEvents = n
		}
	}
	if s.cfg.MessageMetadataDays > 0 {
		cutoff := now.AddDate(0, 0, -s.cfg.MessageMetadataDays)
		if n, err := s.messages.DeleteOlderThan(ctx, cutoff); err != nil {
			s.logger.Error("retention: purge message metadata", "error", err)
		} else {
			res.MessageMetadata = n
		}
	}

	if res.TrackingEvents > 0 || res.MessageMetadata > 0 {
		s.logger.Info("retention sweep complete",
			"tracking_events_deleted", res.TrackingEvents,
			"message_metadata_deleted", res.MessageMetadata)
		// Record the sweep in the audit trail. System action → nil actor:
		// audit_log.admin_id is a UUID FK and a sentinel string fails the insert
		// (the same non-UUID-actor trap that broke scheduled backups).
		if s.audit != nil {
			_ = s.audit.Log(ctx, nil, "retention.sweep", "system", nil, map[string]any{
				"tracking_events_deleted":  res.TrackingEvents,
				"message_metadata_deleted": res.MessageMetadata,
			}, nil)
		}
	}
	return res
}

func (s *Sweeper) loop() {
	ctx := context.Background()
	s.RunOnce(ctx) // sweep once on startup, then on the interval
	ticker := time.NewTicker(s.cfg.RunInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.RunOnce(ctx)
		}
	}
}
