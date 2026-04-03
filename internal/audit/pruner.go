package audit

import (
	"context"
	"log/slog"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// PrunerConfig holds tuning knobs for the audit log pruner.
type PrunerConfig struct {
	RetentionDays int           // entries older than this are deleted; 0 = disabled
	RunInterval   time.Duration // how often the pruner runs; default 24h
}

// DefaultPrunerConfig returns a config with sensible defaults.
func DefaultPrunerConfig() PrunerConfig {
	return PrunerConfig{
		RetentionDays: 90,
		RunInterval:   24 * time.Hour,
	}
}

// Pruner periodically deletes audit log entries older than the configured
// retention period. Follows the same start/stop pattern as monitor.Monitor.
type Pruner struct {
	audit  *repository.AuditRepo
	logger *slog.Logger
	cfg    PrunerConfig
	stopCh chan struct{}
}

// NewPruner creates a new audit log pruner.
func NewPruner(audit *repository.AuditRepo, cfg PrunerConfig, logger *slog.Logger) *Pruner {
	if cfg.RunInterval <= 0 {
		cfg.RunInterval = 24 * time.Hour
	}
	return &Pruner{
		audit:  audit,
		logger: logger,
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
}

// Start begins the pruning loop in a background goroutine.
func (p *Pruner) Start() {
	if p.cfg.RetentionDays <= 0 {
		p.logger.Info("audit log pruner disabled (retention_days=0)")
		return
	}
	p.logger.Info("starting audit log pruner",
		"retention_days", p.cfg.RetentionDays,
		"interval", p.cfg.RunInterval)
	go p.loop()
}

// Stop signals the pruning loop to stop.
func (p *Pruner) Stop() {
	p.logger.Info("stopping audit log pruner")
	close(p.stopCh)
}

// RunOnce executes a single prune pass. Suitable for manual triggering.
func (p *Pruner) RunOnce(ctx context.Context) (int64, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -p.cfg.RetentionDays)
	deleted, err := p.audit.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		p.logger.Error("audit prune failed", "error", err)
		return 0, err
	}
	if deleted > 0 {
		p.logger.Info("audit log pruned", "deleted", deleted, "cutoff", cutoff.Format(time.RFC3339))
	}
	return deleted, nil
}

func (p *Pruner) loop() {
	ctx := context.Background()

	// Run once on startup, then on the interval.
	p.RunOnce(ctx)

	ticker := time.NewTicker(p.cfg.RunInterval)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.RunOnce(ctx)
		}
	}
}
