package auth

import (
	"context"
	"log/slog"
	"time"
)

// SessionCleanerConfig holds tuning knobs for the session cleaner.
type SessionCleanerConfig struct {
	RunInterval time.Duration
}

// DefaultSessionCleanerConfig returns sensible defaults.
func DefaultSessionCleanerConfig() SessionCleanerConfig {
	return SessionCleanerConfig{
		RunInterval: 1 * time.Hour,
	}
}

// SessionCleaner periodically deletes expired session rows from Postgres.
// Valkey entries auto-expire via EX, but the Postgres inventory table
// accumulates rows until they are explicitly removed.
type SessionCleaner struct {
	sm     *SessionManager
	logger *slog.Logger
	cfg    SessionCleanerConfig
	stopCh chan struct{}
}

// NewSessionCleaner creates a session cleaner.
func NewSessionCleaner(sm *SessionManager, cfg SessionCleanerConfig, logger *slog.Logger) *SessionCleaner {
	if cfg.RunInterval <= 0 {
		cfg.RunInterval = 1 * time.Hour
	}
	return &SessionCleaner{
		sm:     sm,
		logger: logger,
		cfg:    cfg,
		stopCh: make(chan struct{}),
	}
}

// Start begins the cleanup loop in a background goroutine.
func (c *SessionCleaner) Start() {
	c.logger.Info("starting session cleaner", "interval", c.cfg.RunInterval)
	go c.loop()
}

// Stop signals the cleanup loop to stop.
func (c *SessionCleaner) Stop() {
	c.logger.Info("stopping session cleaner")
	close(c.stopCh)
}

// RunOnce executes a single cleanup pass.
func (c *SessionCleaner) RunOnce(ctx context.Context) (int64, error) {
	deleted, err := c.sm.CleanExpired(ctx)
	if err != nil {
		c.logger.Error("session cleanup failed", "error", err)
		return 0, err
	}
	if deleted > 0 {
		c.logger.Info("expired sessions pruned", "deleted", deleted)
	}
	return deleted, nil
}

func (c *SessionCleaner) loop() {
	ctx := context.Background()

	c.RunOnce(ctx)

	ticker := time.NewTicker(c.cfg.RunInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			c.RunOnce(ctx)
		}
	}
}
