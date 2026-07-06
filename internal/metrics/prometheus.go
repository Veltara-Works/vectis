package metrics

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "vectis"

// Collector implements prometheus.Collector and exposes Vectis metrics.
type Collector struct {
	db     *pgxpool.Pool
	logger *slog.Logger

	// Gauges
	domainsTotal       *prometheus.Desc
	domainsActive      *prometheus.Desc
	mailboxesTotal     *prometheus.Desc
	mailboxesSuspended *prometheus.Desc
	aliasesTotal       *prometheus.Desc
	adminsTotal        *prometheus.Desc
	apiKeysActive      *prometheus.Desc
	webhooksActive     *prometheus.Desc
	abuseUnresolved    *prometheus.Desc

	// DB pool
	dbPoolSize  *prometheus.Desc
	dbPoolInUse *prometheus.Desc
}

// NewCollector creates a Prometheus collector backed by Postgres.
func NewCollector(db *pgxpool.Pool, logger *slog.Logger) *Collector {
	return &Collector{
		db:     db,
		logger: logger,

		domainsTotal:       prometheus.NewDesc(namespace+"_domains_total", "Total number of domains", nil, nil),
		domainsActive:      prometheus.NewDesc(namespace+"_domains_active", "Number of active domains", nil, nil),
		mailboxesTotal:     prometheus.NewDesc(namespace+"_mailboxes_total", "Total number of mailboxes", nil, nil),
		mailboxesSuspended: prometheus.NewDesc(namespace+"_mailboxes_suspended", "Mailboxes suspended from sending", nil, nil),
		aliasesTotal:       prometheus.NewDesc(namespace+"_aliases_total", "Total number of aliases", nil, nil),
		adminsTotal:        prometheus.NewDesc(namespace+"_admins_total", "Total number of admin accounts", nil, nil),
		apiKeysActive:      prometheus.NewDesc(namespace+"_api_keys_active", "Number of active API keys", nil, nil),
		webhooksActive:     prometheus.NewDesc(namespace+"_webhooks_active", "Number of active webhooks", nil, nil),
		abuseUnresolved:    prometheus.NewDesc(namespace+"_abuse_events_unresolved", "Unresolved abuse events", nil, nil),

		dbPoolSize:  prometheus.NewDesc(namespace+"_db_pool_size", "Database connection pool max size", nil, nil),
		dbPoolInUse: prometheus.NewDesc(namespace+"_db_pool_in_use", "Database connections currently in use", nil, nil),
	}
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.domainsTotal
	ch <- c.domainsActive
	ch <- c.mailboxesTotal
	ch <- c.mailboxesSuspended
	ch <- c.aliasesTotal
	ch <- c.adminsTotal
	ch <- c.apiKeysActive
	ch <- c.webhooksActive
	ch <- c.abuseUnresolved
	ch <- c.dbPoolSize
	ch <- c.dbPoolInUse
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	ctx := context.Background()

	c.collectGauge(ctx, ch, c.domainsTotal, "SELECT COUNT(*) FROM domains")
	c.collectGauge(ctx, ch, c.domainsActive, "SELECT COUNT(*) FROM domains WHERE active = true")
	c.collectGauge(ctx, ch, c.mailboxesTotal, "SELECT COUNT(*) FROM mailboxes")
	c.collectGauge(ctx, ch, c.mailboxesSuspended, "SELECT COUNT(*) FROM mailboxes WHERE send_suspended = true")
	c.collectGauge(ctx, ch, c.aliasesTotal, "SELECT COUNT(*) FROM aliases")
	c.collectGauge(ctx, ch, c.adminsTotal, "SELECT COUNT(*) FROM admins")
	c.collectGauge(ctx, ch, c.apiKeysActive, "SELECT COUNT(*) FROM api_keys WHERE active = true AND (expires_at IS NULL OR expires_at > NOW())")
	c.collectGauge(ctx, ch, c.webhooksActive, "SELECT COUNT(*) FROM webhooks WHERE active = true")
	c.collectGauge(ctx, ch, c.abuseUnresolved, "SELECT COUNT(*) FROM abuse_events WHERE resolved = false")

	// DB pool stats.
	stat := c.db.Stat()
	ch <- prometheus.MustNewConstMetric(c.dbPoolSize, prometheus.GaugeValue, float64(stat.MaxConns()))
	ch <- prometheus.MustNewConstMetric(c.dbPoolInUse, prometheus.GaugeValue, float64(stat.AcquiredConns()))
}

func (c *Collector) collectGauge(ctx context.Context, ch chan<- prometheus.Metric, desc *prometheus.Desc, query string) {
	var count int64
	if err := c.db.QueryRow(ctx, query).Scan(&count); err != nil {
		c.logger.Debug("prometheus metric query failed", "error", err, "query", query)
		return
	}
	ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(count))
}
