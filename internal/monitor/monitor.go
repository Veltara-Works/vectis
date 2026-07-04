package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go"

	"github.com/Veltara-Works/vectis/internal/backup"
	"github.com/Veltara-Works/vectis/internal/repository"
	vectistls "github.com/Veltara-Works/vectis/internal/tls"
)

// Config holds tuning knobs for the health monitor.
type Config struct {
	CheckInterval   time.Duration // default 60s
	DiskWarnPercent int           // default 80
	QueueWarnSize   int           // default 100
	CertWarnDays    int           // default 14
	CertDir         string        // path to TLS certificate directory

	// Backup-age check (C-1). When BackupEnabled is true the monitor flags a
	// stale or absent last-successful-backup. Schedule/Timezone are the effective
	// backup cron settings, used to derive the expected interval between runs.
	BackupEnabled  bool
	BackupSchedule string
	BackupTimezone string
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
	db          *pgxpool.Pool
	vk          valkey.Client
	alerter     *Alerter
	logger      *slog.Logger
	cfg         Config
	stopCh      chan struct{}
	startOnce   sync.Once        // guards Start so a double call can't spawn two loops
	stopOnce    sync.Once        // guards Stop so a double call can't panic on close(stopCh)
	dockerCLI   bool             // whether the `docker` CLI is on PATH
	postfixExec bool             // whether `docker exec vectis-postfix` is viable (implies dockerCLI)
	now         func() time.Time // injectable for tests; defaults to time.Now

	// backupProvider, when set, returns the LIVE effective backup settings on
	// every check. Preferred over the static cfg.Backup* fields so a runtime
	// schedule change (admin UI) can't leave the staleness threshold pinned to a
	// stale, longer interval — which would under-alert (a reintroduced blind spot).
	backupProvider func() (enabled bool, schedule, timezone string)
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
		now:         time.Now,
	}
}

// SetBackupSettingsProvider installs a callback returning the live effective
// backup settings, used by the backup-age check (C-1) in preference to the
// static cfg.Backup* snapshot so runtime schedule changes take effect without a
// restart. Call before Start.
func (m *Monitor) SetBackupSettingsProvider(fn func() (enabled bool, schedule, timezone string)) {
	m.backupProvider = fn
}

// Start begins the monitoring loop in a background goroutine. Idempotent: a
// second call is a no-op rather than spawning a duplicate loop.
func (m *Monitor) Start() {
	m.startOnce.Do(func() {
		m.logger.Info("starting health monitor", "interval", m.cfg.CheckInterval)
		go m.loop()
	})
}

// Stop signals the monitoring loop to stop. Idempotent: a second call is a no-op
// rather than panicking on close of an already-closed channel.
func (m *Monitor) Stop() {
	m.stopOnce.Do(func() {
		m.logger.Info("stopping health monitor")
		close(m.stopCh)
	})
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
	m.checkBackupAge(ctx)
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
		// Namespaced distinctly from the liveness checks (checkPostgres/checkValkey
		// alert on service "postgres"/"valkey"). A container being "running" must
		// NOT resolve a "postgres is unreachable" liveness alert — the container can
		// be up while the DB itself is wedged. Keying container-health on
		// "container-<svc>" keeps the two failure modes in separate dedup namespaces.
		service := "container-" + strings.TrimPrefix(name, "vectis-")

		status, err := dockerContainerHealth(ctx, name)
		if err != nil {
			m.logger.Debug("container health check failed", "container", name, "error", err)
			m.alerter.Send(ctx, "ERROR", service,
				fmt.Sprintf("Container %s is not running or unreachable: %v", name, err))
			m.alerter.ResolveServiceExcept(ctx, service, "error")
			continue
		}

		switch status {
		case "healthy", "running":
			// Clear whichever tier (error/warn) was firing for this container.
			m.alerter.ResolveService(ctx, service)
		case "unhealthy":
			m.alerter.Send(ctx, "ERROR", service,
				fmt.Sprintf("Container %s health check reports unhealthy", name))
			m.alerter.ResolveServiceExcept(ctx, service, "error")
		default:
			m.alerter.Send(ctx, "WARN", service,
				fmt.Sprintf("Container %s in unexpected state: %s", name, status))
			m.alerter.ResolveServiceExcept(ctx, service, "warn")
		}
	}
}

// checkDiskUsage checks disk usage on /var/vectis/mail and the Postgres data
// directory using `df`.
func (m *Monitor) checkDiskUsage(ctx context.Context) {
	// The pg-data-dir disk check is namespaced "disk-postgres", NOT "postgres" —
	// otherwise its WARN collides on dedup key "postgres:warn" with the
	// connection-pool-hot WARN from checkPostgres, and the 15-min dedup window
	// lets one silently mask the other.
	paths := []struct {
		path    string
		service string
	}{
		{"/var/vectis/mail", "disk"},
		{"/var/lib/postgresql/data", "disk-postgres"},
	}

	for _, p := range paths {
		pct, err := diskUsagePercent(ctx, p.path)
		if err != nil {
			m.logger.Debug("disk check failed", "path", p.path, "error", err)
			continue
		}

		// Resolve keys are derived by the alerter from the same (service, severity)
		// pair Send uses, so a healthy edge clears exactly what a prior WARN/CRITICAL
		// wrote (the old code resolved a hand-written "<svc>:disk" key that Send never
		// set → disk alerts never auto-resolved).
		if pct >= 95 {
			m.alerter.Send(ctx, "CRITICAL", p.service,
				fmt.Sprintf("Disk usage at %d%% on %s — critically low space", pct, p.path))
			m.alerter.ResolveServiceExcept(ctx, p.service, "critical")
		} else if pct >= m.cfg.DiskWarnPercent {
			m.alerter.Send(ctx, "WARN", p.service,
				fmt.Sprintf("Disk usage at %d%% on %s (threshold: %d%%)", pct, p.path, m.cfg.DiskWarnPercent))
			m.alerter.ResolveServiceExcept(ctx, p.service, "warn")
		} else {
			m.alerter.ResolveService(ctx, p.service)
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
		m.alerter.ResolveService(ctx, "queue")
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
		m.alerter.ResolveServiceExcept(ctx, "tls", "critical")
	} else if info.DaysLeft <= m.cfg.CertWarnDays {
		m.alerter.Send(ctx, "WARN", "tls",
			fmt.Sprintf("TLS certificate expires in %d days (subject: %s)", info.DaysLeft, info.Subject))
		m.alerter.ResolveServiceExcept(ctx, "tls", "warn")
	} else {
		// Clears both tls:warn and tls:critical — the old code resolved only
		// tls:warn, so a renewed cert never cleared a prior expiry CRITICAL.
		m.alerter.ResolveService(ctx, "tls")
	}
}

// backupAgeState is the outcome of the backup-age decision.
type backupAgeState int

const (
	backupAgeOK    backupAgeState = iota // a recent successful backup exists
	backupAgeNever                       // no backup has ever completed
	backupAgeStale                       // the newest backup is older than the grace-adjusted interval
)

// evalBackupAge is the pure decision for the backup-age check, split out so the
// staleness logic is unit-testable without a database. last is the newest
// completed-backup time (nil = none ever), maxInterval is the expected longest
// gap between scheduled runs; a backup is stale once it is older than
// maxInterval * backup.StaleGraceFactor.
func evalBackupAge(last *time.Time, now time.Time, maxInterval time.Duration) backupAgeState {
	if last == nil {
		return backupAgeNever
	}
	threshold := time.Duration(float64(maxInterval) * backup.StaleGraceFactor)
	if now.Sub(*last) > threshold {
		return backupAgeStale
	}
	return backupAgeOK
}

// checkBackupAge flags a stale or absent last-successful-backup (C-1). It closes
// the invisibility gap that let nightly backups fail unnoticed: "no backup on
// record" fires WARN, an existing-but-stale backup escalates to CRITICAL, and a
// healthy edge resolves both. Skipped entirely when backups are disabled.
func (m *Monitor) checkBackupAge(ctx context.Context) {
	// Prefer the live provider (reflects runtime schedule changes); fall back to
	// the static snapshot captured at construction.
	enabled, schedule, timezone := m.cfg.BackupEnabled, m.cfg.BackupSchedule, m.cfg.BackupTimezone
	if m.backupProvider != nil {
		enabled, schedule, timezone = m.backupProvider()
	}
	if !enabled || m.db == nil {
		return
	}
	// Bound the DB query so a hung/slow Postgres can't stall the shared monitor
	// loop (which runs on context.Background()) — same 5s cap the other DB-backed
	// checks here use (checkPostgres/checkValkey).
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	last, err := repository.NewBackupRepo(m.db).LatestCompleted(queryCtx)
	if err != nil {
		m.logger.Debug("backup age check: query failed", "error", err)
		return
	}
	now := m.now()

	if last == nil {
		// never: WARN, and silently clear any prior stale-CRITICAL so an
		// oscillation (stale → job rows cleared → never) doesn't leave it stuck
		// open (still a WARN condition, so no "now healthy" recovery).
		m.alerter.Send(ctx, "WARN", "backup", "no completed backup on record")
		m.alerter.ResolveServiceExcept(ctx, "backup", "warn")
		return
	}

	maxInterval, err := backup.ExpectedInterval(schedule, timezone, now, 8)
	if err != nil {
		m.logger.Debug("backup age check: schedule parse failed", "error", err)
		return
	}

	// Each terminal branch silently clears the sibling key so a transition without
	// an intervening healthy cycle never leaves the opposite alert stuck open; the
	// healthy edge clears both tiers WITH a recovery notification.
	switch evalBackupAge(last, now, maxInterval) {
	case backupAgeStale:
		age := now.Sub(*last).Round(time.Minute)
		m.alerter.Send(ctx, "CRITICAL", "backup",
			fmt.Sprintf("last successful backup was %s ago (expected within ~%s)",
				age, time.Duration(float64(maxInterval)*backup.StaleGraceFactor).Round(time.Minute)))
		m.alerter.ResolveServiceExcept(ctx, "backup", "critical")
	default: // backupAgeOK
		m.alerter.ResolveService(ctx, "backup")
	}
}

// checkPostgres verifies the database connection pool is healthy.
func (m *Monitor) checkPostgres(ctx context.Context) {
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := m.db.Ping(checkCtx); err != nil {
		m.alerter.Send(ctx, "ERROR", "postgres",
			fmt.Sprintf("Postgres ping failed: %v", err))
		m.alerter.ResolveServiceExcept(ctx, "postgres", "error")
		return
	}

	stat := m.db.Stat()
	total := stat.MaxConns()
	inUse := stat.AcquiredConns()

	// Warn if >80% of pool is consumed.
	if total > 0 && float64(inUse)/float64(total) > 0.8 {
		m.alerter.Send(ctx, "WARN", "postgres",
			fmt.Sprintf("Postgres connection pool running hot: %d/%d connections in use", inUse, total))
		m.alerter.ResolveServiceExcept(ctx, "postgres", "warn")
	} else {
		// Clears both postgres:error and postgres:warn — the old code resolved only
		// postgres:error, so a cooled-down pool never cleared its prior WARN.
		m.alerter.ResolveService(ctx, "postgres")
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
		m.alerter.ResolveServiceExcept(ctx, "valkey", "error")
	} else {
		m.alerter.ResolveService(ctx, "valkey")
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
	return parseDfPercent(out)
}

// parseDfPercent extracts the usage percentage from `df --output=pcent` output,
// which looks like:
//
//	Use%
//	 42%
//
// Split out from diskUsagePercent so the parsing can be unit-tested without
// shelling out to df.
func parseDfPercent(out []byte) (int, error) {
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
	return parsePostqueueCount(out)
}

// parsePostqueueCount counts queued messages from `postqueue -p` output. It
// prefers the trailing "-- <size> <unit> in <count> Requests." summary line and
// falls back to counting hex-prefixed queue-entry lines. Split out from
// mailQueueSize so the parsing can be unit-tested without a running Postfix.
func parsePostqueueCount(out []byte) (int, error) {
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
