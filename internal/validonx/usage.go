package validonx

import (
	"context"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// UsageReporter periodically collects and reports usage metrics to ValidonX.
// Follows the same start/stop pattern as monitor.Monitor.
type UsageReporter struct {
	client *Client
	db     *pgxpool.Pool
	logger *slog.Logger
	stopCh chan struct{}

	flushInterval time.Duration
}

// NewUsageReporter creates a usage reporter. Returns nil if ValidonX is not configured.
func NewUsageReporter(client *Client, db *pgxpool.Pool, logger *slog.Logger) *UsageReporter {
	if client == nil || !client.Configured() {
		return nil
	}
	return &UsageReporter{
		client:        client,
		db:            db,
		logger:        logger,
		stopCh:        make(chan struct{}),
		flushInterval: 1 * time.Hour,
	}
}

// Start begins the periodic usage reporting loop.
func (r *UsageReporter) Start() {
	if r == nil {
		return
	}
	r.logger.Info("starting ValidonX usage reporter", "interval", r.flushInterval)
	go r.loop()
}

// Stop signals the reporting loop to stop.
func (r *UsageReporter) Stop() {
	if r == nil {
		return
	}
	r.logger.Info("stopping ValidonX usage reporter")
	close(r.stopCh)
}

func (r *UsageReporter) loop() {
	// Report on startup.
	r.flush()

	ticker := time.NewTicker(r.flushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.flush()
		}
	}
}

// flush collects current usage stats and reports them to ValidonX.
func (r *UsageReporter) flush() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	stats, err := r.collectStats(ctx)
	if err != nil {
		r.logger.Error("failed to collect usage stats", "error", err)
		return
	}

	event := BillingEvent{
		Type:     "usage.report",
		TenantID: r.client.TenantID(),
		ServerID: r.client.ServerID(),
		Details:  stats,
	}

	if err := r.client.LogBillingEvent(ctx, event); err != nil {
		r.logger.Warn("failed to report usage to ValidonX (will retry next cycle)", "error", err)
		return
	}

	r.logger.Info("usage metrics reported to ValidonX", "domains", stats["domains"], "mailboxes", stats["mailboxes"])
}

// collectStats queries Postgres for current usage counts.
func (r *UsageReporter) collectStats(ctx context.Context) (map[string]any, error) {
	stats := make(map[string]any)

	queries := map[string]string{
		"domains":            "SELECT COUNT(*) FROM domains",
		"domains_active":     "SELECT COUNT(*) FROM domains WHERE active = true",
		"mailboxes":          "SELECT COUNT(*) FROM mailboxes",
		"mailboxes_active":   "SELECT COUNT(*) FROM mailboxes WHERE active = true",
		"aliases":            "SELECT COUNT(*) FROM aliases",
		"admins":             "SELECT COUNT(*) FROM admins",
		"api_keys_active":    "SELECT COUNT(*) FROM api_keys WHERE active = true AND (expires_at IS NULL OR expires_at > NOW())",
		"emails_sent_24h":    "SELECT COUNT(*) FROM audit_log WHERE action = 'mail.send' AND created_at > NOW() - INTERVAL '24 hours'",
		"emails_received_24h": "SELECT COUNT(*) FROM audit_log WHERE action = 'mail.receive' AND created_at > NOW() - INTERVAL '24 hours'",
		"storage_bytes":      "SELECT COALESCE(SUM(pg_database_size(current_database())), 0)",
	}

	for key, query := range queries {
		var count int64
		if err := r.db.QueryRow(ctx, query).Scan(&count); err != nil {
			r.logger.Debug("usage stat query failed", "key", key, "error", err)
			stats[key] = 0
			continue
		}
		stats[key] = count
	}

	stats["reported_at"] = time.Now().UTC().Format(time.RFC3339)
	return stats, nil
}
