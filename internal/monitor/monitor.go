package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go"

	vectistls "github.com/Veltara-Works/vectis/internal/tls"
)

// Config holds tuning knobs for the health monitor.
type Config struct {
	CheckInterval   time.Duration // default 60s
	DiskWarnPercent int           // default 80
	QueueWarnSize   int           // default 100
	CertWarnDays    int           // default 14
	CertDir         string        // path to TLS certificate directory
}

// DefaultConfig returns Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		CheckInterval:   60 * time.Second,
		DiskWarnPercent: 80,
		QueueWarnSize:   100,
		CertWarnDays:    14,
		CertDir:         "/var/vectis/certs",
	}
}

// Monitor runs periodic health checks against all Vectis services and
// dispatches alerts when thresholds are exceeded.
type Monitor struct {
	db           *pgxpool.Pool
	vk           valkey.Client
	alerter      *Alerter
	logger       *slog.Logger
	cfg          Config
	stopCh       chan struct{}
	dockerCLI    bool // whether the `docker` CLI is on PATH
	postfixExec  bool // whether `docker exec vectis-postfix` is viable (implies dockerCLI)
}

// New creates a new health monitor.
func New(db *pgxpool.Pool, vk valkey.Client, alerter *Alerter, cfg Config, logger *slog.Logger) *Monitor {
	if cfg.CheckInterval <= 0 {
		cfg.CheckInterval = 60 * time.Second
	}
	if cfg.DiskWarnPercent <= 0 {
		cfg.DiskWarnPercent = 80
	}
	if cfg.QueueWarnSize <= 0 {
		cfg.QueueWarnSize = 100
	}
	if cfg.CertWarnDays <= 0 {
		cfg.CertWarnDays = 14
	}

	// The api image ships without a `docker` CLI on purpose — only the
	// orchestrator holds the Docker socket. Detect that absence here
	// and skip the two checks that shell out to docker rather than
	// emitting spurious ERROR alerts for every service every minute.
	// Long-term these checks belong in the orchestrator (deferred-items
	// §10); this is the rc25 stop-gap.
	_, dockerErr := exec.LookPath("docker")
	dockerCLI := dockerErr == nil
	if !dockerCLI {
		logger.Warn("docker CLI not on PATH — container-health and mail-queue checks will be skipped (expected inside the api container)")
	}

	return &Monitor{
		db:          db,
		vk:          vk,
		alerter:     alerter,
		logger:      logger,
		cfg:         cfg,
		stopCh:      make(chan struct{}),
		dockerCLI:   dockerCLI,
		postfixExec: dockerCLI,
	}
}

// Start begins the monitoring loop in a background goroutine.
func (m *Monitor) Start() {
	m.logger.Info("starting health monitor", "interval", m.cfg.CheckInterval)
	go m.loop()
}

// Stop signals the monitoring loop to stop.
func (m *Monitor) Stop() {
	m.logger.Info("stopping health monitor")
	close(m.stopCh)
}

// RunCheck executes all health checks once. Suitable for manual triggering
// via API or CLI.
func (m *Monitor) RunCheck(ctx context.Context) {
	m.logger.Debug("running health checks")

	if m.dockerCLI {
		m.checkContainerHealth(ctx)
	}
	m.checkDiskUsage(ctx)
	if m.postfixExec {
		m.checkMailQueue(ctx)
	}
	m.checkCertExpiry(ctx)
	m.checkPostgres(ctx)
	m.checkValkey(ctx)
}

func (m *Monitor) loop() {
	// Run an initial check immediately on start.
	ctx := context.Background()
	m.RunCheck(ctx)

	ticker := time.NewTicker(m.cfg.CheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.RunCheck(ctx)
		}
	}
}

// ---------------------------------------------------------------------------
// Individual health checks
// ---------------------------------------------------------------------------

// vectisServices is the list of Docker container names we monitor.
var vectisServices = []string{
	"vectis-postfix",
	"vectis-dovecot",
	"vectis-rspamd",
	"vectis-traefik",
	"vectis-postgres",
	"vectis-valkey",
}

// checkContainerHealth checks Docker container health status for all Vectis
// services by running `docker inspect --format`.
func (m *Monitor) checkContainerHealth(ctx context.Context) {
	for _, name := range vectisServices {
		status, err := dockerContainerHealth(ctx, name)
		if err != nil {
			m.logger.Debug("container health check failed", "container", name, "error", err)
			service := strings.TrimPrefix(name, "vectis-")
			m.alerter.Send(ctx, "ERROR", service,
				fmt.Sprintf("Container %s is not running or unreachable: %v", name, err))
			continue
		}

		service := strings.TrimPrefix(name, "vectis-")

		switch status {
		case "healthy", "running":
			// Resolve any prior alert for this service.
			m.alerter.Resolve(ctx, service+":error")
		case "unhealthy":
			m.alerter.Send(ctx, "ERROR", service,
				fmt.Sprintf("Container %s health check reports unhealthy", name))
		default:
			m.alerter.Send(ctx, "WARN", service,
				fmt.Sprintf("Container %s in unexpected state: %s", name, status))
		}
	}
}

// checkDiskUsage checks disk usage on /var/vectis/mail and the Postgres data
// directory using `df`.
func (m *Monitor) checkDiskUsage(ctx context.Context) {
	paths := []struct {
		path    string
		service string
	}{
		{"/var/vectis/mail", "disk"},
		{"/var/lib/postgresql/data", "postgres"},
	}

	for _, p := range paths {
		pct, err := diskUsagePercent(ctx, p.path)
		if err != nil {
			m.logger.Debug("disk check failed", "path", p.path, "error", err)
			continue
		}

		dedupKey := p.service + ":disk"
		if pct >= 95 {
			m.alerter.Send(ctx, "CRITICAL", p.service,
				fmt.Sprintf("Disk usage at %d%% on %s — critically low space", pct, p.path))
		} else if pct >= m.cfg.DiskWarnPercent {
			m.alerter.Send(ctx, "WARN", p.service,
				fmt.Sprintf("Disk usage at %d%% on %s (threshold: %d%%)", pct, p.path, m.cfg.DiskWarnPercent))
		} else {
			m.alerter.Resolve(ctx, dedupKey)
		}
	}
}

// checkMailQueue checks the Postfix mail queue length by running
// `docker exec vectis-postfix postqueue -p` and counting entries.
func (m *Monitor) checkMailQueue(ctx context.Context) {
	size, err := mailQueueSize(ctx)
	if err != nil {
		m.logger.Debug("mail queue check failed", "error", err)
		return
	}

	if size >= m.cfg.QueueWarnSize {
		m.alerter.Send(ctx, "WARN", "queue",
			fmt.Sprintf("Mail queue has %d messages (threshold: %d)", size, m.cfg.QueueWarnSize))
	} else {
		m.alerter.Resolve(ctx, "queue:warn")
	}
}

// checkCertExpiry checks TLS certificate expiry dates.
func (m *Monitor) checkCertExpiry(ctx context.Context) {
	certPath := filepath.Join(m.cfg.CertDir, "fullchain.pem")
	info, err := vectistls.ReadCertInfo(certPath)
	if err != nil {
		m.logger.Debug("cert expiry check failed", "error", err)
		return
	}

	if info.IsExpired {
		m.alerter.Send(ctx, "CRITICAL", "tls",
			fmt.Sprintf("TLS certificate has expired (subject: %s)", info.Subject))
	} else if info.DaysLeft <= m.cfg.CertWarnDays {
		m.alerter.Send(ctx, "WARN", "tls",
			fmt.Sprintf("TLS certificate expires in %d days (subject: %s)", info.DaysLeft, info.Subject))
	} else {
		m.alerter.Resolve(ctx, "tls:warn")
	}
}

// checkPostgres verifies the database connection pool is healthy.
func (m *Monitor) checkPostgres(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := m.db.Ping(checkCtx); err != nil {
		m.alerter.Send(ctx, "ERROR", "postgres",
			fmt.Sprintf("Postgres ping failed: %v", err))
		return
	}

	stat := m.db.Stat()
	total := stat.MaxConns()
	inUse := stat.AcquiredConns()

	// Warn if >80% of pool is consumed.
	if total > 0 && float64(inUse)/float64(total) > 0.8 {
		m.alerter.Send(ctx, "WARN", "postgres",
			fmt.Sprintf("Postgres connection pool running hot: %d/%d connections in use", inUse, total))
	} else {
		m.alerter.Resolve(ctx, "postgres:error")
	}
}

// checkValkey verifies the Valkey connection is healthy.
func (m *Monitor) checkValkey(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := m.vk.B().Ping().Build()
	if err := m.vk.Do(checkCtx, cmd).Error(); err != nil {
		m.alerter.Send(ctx, "ERROR", "valkey",
			fmt.Sprintf("Valkey ping failed: %v", err))
	} else {
		m.alerter.Resolve(ctx, "valkey:error")
	}
}

// ---------------------------------------------------------------------------
// Shell helpers — encapsulate exec.Command calls for testability
// ---------------------------------------------------------------------------

// dockerContainerHealth returns the health/status string for a Docker
// container. It tries Health.Status first; if the container has no
// healthcheck it falls back to State.Status.
func dockerContainerHealth(ctx context.Context, containerName string) (string, error) {
	// Try health status first.
	out, err := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}",
		containerName,
	).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker inspect %s: %s — %w", containerName, strings.TrimSpace(string(out)), err)
	}
	return strings.TrimSpace(string(out)), nil
}

// diskUsagePercent returns the disk usage percentage for the filesystem
// containing the given path.
func diskUsagePercent(ctx context.Context, path string) (int, error) {
	out, err := exec.CommandContext(ctx, "df", "--output=pcent", path).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("df %s: %w", path, err)
	}

	// Output is like:
	// Use%
	//  42%
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return 0, fmt.Errorf("unexpected df output: %s", string(out))
	}

	pctStr := strings.TrimSpace(lines[len(lines)-1])
	pctStr = strings.TrimSuffix(pctStr, "%")
	pct, err := strconv.Atoi(pctStr)
	if err != nil {
		return 0, fmt.Errorf("parse disk usage percent: %w", err)
	}
	return pct, nil
}

// mailQueueSize returns the number of messages in the Postfix mail queue
// by parsing `docker exec vectis-postfix postqueue -p` output.
func mailQueueSize(ctx context.Context) (int, error) {
	out, err := exec.CommandContext(ctx, "docker", "exec", "vectis-postfix",
		"postqueue", "-p",
	).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("postqueue -p: %w", err)
	}

	output := strings.TrimSpace(string(out))

	// Empty queue says "Mail queue is empty".
	if strings.Contains(output, "Mail queue is empty") {
		return 0, nil
	}

	// The last line of postqueue -p output is like:
	// -- 42 Kbytes in 15 Requests.
	lines := strings.Split(output, "\n")
	lastLine := strings.TrimSpace(lines[len(lines)-1])

	// Parse "-- <size> <unit> in <count> Requests."
	if strings.HasPrefix(lastLine, "--") {
		parts := strings.Fields(lastLine)
		// Format: -- <size> <unit> in <count> Requests.
		for i, p := range parts {
			if p == "in" && i+1 < len(parts) {
				count, err := strconv.Atoi(parts[i+1])
				if err != nil {
					return 0, fmt.Errorf("parse queue count: %w", err)
				}
				return count, nil
			}
		}
	}

	// Fallback: count lines that look like queue entries (start with hex ID).
	count := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) > 0 && isHexPrefix(line) {
			count++
		}
	}
	return count, nil
}

// isHexPrefix returns true if the first character of s is a hex digit,
// which identifies a Postfix queue entry line.
func isHexPrefix(s string) bool {
	if len(s) == 0 {
		return false
	}
	c := s[0]
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
}
