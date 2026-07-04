package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/repository"
)

const dedupWindow = 15 * time.Minute

// emailSendTimeout bounds the whole SMTP exchange (dial + envelope + data). The
// monitor loop dispatches alert email synchronously on a single goroutine, so an
// unbounded net/smtp.SendMail against a hung Postfix would stall the ticker and
// every subsequent health check — the exact stall the DB/Valkey checks already
// guard with a 5s context. Bound it here too.
const emailSendTimeout = 15 * time.Second

// alertSeverityTiers are every severity a service health check can raise. The
// resolve helpers clear these for a service so a firing→lower-severity or
// firing→healthy transition never strands the opposite key open (the class of
// bug where checkDiskUsage fired `svc:critical` but only ever resolved a key
// nothing wrote). Keep in sync with the severities passed to Send.
var alertSeverityTiers = []string{"warn", "critical", "error"}

// dedupKeyFor is the single source of truth for an alert's dedup key. Send
// derives the key this way; every Resolve path MUST derive it the same way, so
// the two can't drift. Severity is lower-cased to match the historical scheme.
func dedupKeyFor(service, severity string) string {
	return service + ":" + strings.ToLower(severity)
}

// serviceResolveKeys returns the dedup keys to clear when a service is healthy —
// every severity tier for that service. Pure (no I/O) so the key contract is
// unit-testable without a database.
func serviceResolveKeys(service string) []string {
	keys := make([]string, 0, len(alertSeverityTiers))
	for _, sev := range alertSeverityTiers {
		keys = append(keys, dedupKeyFor(service, sev))
	}
	return keys
}

// serviceResolveKeysExcept returns the sibling dedup keys to clear when a service
// fires at keepSeverity — every tier except the one just raised. Pure so it is
// unit-testable.
func serviceResolveKeysExcept(service, keepSeverity string) []string {
	keep := strings.ToLower(keepSeverity)
	keys := make([]string, 0, len(alertSeverityTiers))
	for _, sev := range alertSeverityTiers {
		if sev == keep {
			continue
		}
		keys = append(keys, dedupKeyFor(service, sev))
	}
	return keys
}

// webhookPayload is the JSON body sent to configured webhook endpoints.
type webhookPayload struct {
	Severity        string `json:"severity"`
	Service         string `json:"service"`
	Message         string `json:"message"`
	Timestamp       string `json:"timestamp"`
	Hostname        string `json:"hostname"`
	ActionTaken     string `json:"action_taken"`
	SuggestedAction string `json:"suggested_action"`
}

// Alerter dispatches alerts via email and/or webhook and records them for
// deduplication.
type Alerter struct {
	alerts     *repository.AlertRepo
	emailCfg   config.AlertEmailConfig
	webhookCfg config.AlertWebhookConfig
	hostname   string
	logger     *slog.Logger
}

// NewAlerter creates a new alert dispatcher. If the email config is
// enabled but SMTPHost is empty, this logs a single warning at startup
// and treats email as disabled — the previous behaviour of dialing
// 127.0.0.1:25 inside the api container always failed silently.
func NewAlerter(alerts *repository.AlertRepo, emailCfg config.AlertEmailConfig, webhookCfg config.AlertWebhookConfig, hostname string, logger *slog.Logger) *Alerter {
	if emailCfg.Enabled && emailCfg.SMTPHost == "" {
		logger.Warn("email alerts enabled but alerts.email.smtp_host is empty — email delivery disabled until set (e.g. 'vectis-postfix:25')")
	}
	if emailCfg.Enabled && len(emailCfg.Recipients) == 0 {
		logger.Warn("email alerts enabled but alerts.email.recipients is empty — email delivery disabled until set")
	}
	return &Alerter{
		alerts:     alerts,
		emailCfg:   emailCfg,
		webhookCfg: webhookCfg,
		hostname:   hostname,
		logger:     logger,
	}
}

// emailReady reports whether email delivery has a chance of succeeding.
// Gate every Send/Resolve path through this so we don't dial an empty
// host or send to zero recipients.
func (a *Alerter) emailReady() bool {
	return a.emailCfg.Enabled && a.emailCfg.SMTPHost != "" && len(a.emailCfg.Recipients) > 0
}

// Send dispatches an alert through configured channels. It deduplicates by
// checking whether the same dedup key was sent within the last 15 minutes.
// CRITICAL severity bypasses dedup and is always sent immediately.
func (a *Alerter) Send(ctx context.Context, severity, service, message string) {
	dedupKey := dedupKeyFor(service, severity)

	// Dedup check: skip if same alert was sent recently (except CRITICAL).
	if !strings.EqualFold(severity, "CRITICAL") {
		recent, err := a.alerts.FindRecent(ctx, dedupKey, dedupWindow)
		if err != nil {
			a.logger.Error("alert dedup lookup failed", "error", err)
			// Proceed with sending rather than silently dropping.
		} else if recent != nil {
			a.logger.Debug("alert deduplicated", "dedup_key", dedupKey, "last_sent", recent.SentAt)
			return
		}
	}

	// Record alert in history.
	if err := a.alerts.Log(ctx, severity, service, message, dedupKey); err != nil {
		a.logger.Error("failed to log alert", "error", err)
	}

	suggestedAction := suggestAction(service)

	// Send via email.
	if a.emailReady() {
		a.sendEmail(severity, service, message, suggestedAction)
	}

	// Send via webhook.
	if a.webhookCfg.Enabled && a.webhookCfg.URL != "" {
		a.sendWebhook(ctx, severity, service, message, suggestedAction)
	}

	a.logger.Warn("alert sent",
		"severity", severity,
		"service", service,
		"message", message,
	)
}

// Resolve marks an alert condition as resolved and sends a recovery
// notification through configured channels.
func (a *Alerter) Resolve(ctx context.Context, dedupKey string) {
	resolved, err := a.alerts.Resolve(ctx, dedupKey)
	if err != nil {
		a.logger.Error("failed to resolve alert", "dedup_key", dedupKey, "error", err)
		return
	}

	// Nothing was actually firing for this key — the monitor calls Resolve on
	// every healthy check cycle (every 60s), so without this guard we'd log
	// "alert resolved" and fire a recovery email/webhook every minute for a
	// service that never alerted. Only notify on a real firing→resolved edge.
	if resolved == 0 {
		return
	}

	parts := strings.SplitN(dedupKey, ":", 2)
	service := dedupKey
	if len(parts) > 0 {
		service = parts[0]
	}

	recoveryMsg := fmt.Sprintf("RESOLVED: %s is now healthy", service)

	if a.emailReady() {
		a.sendEmail("INFO", service, recoveryMsg, "No action required.")
	}

	if a.webhookCfg.Enabled && a.webhookCfg.URL != "" {
		a.sendWebhook(ctx, "INFO", service, recoveryMsg, "No action required.")
	}

	a.logger.Info("alert resolved", "dedup_key", dedupKey)
}

// ResolveService clears every severity tier for a service — the correct call on
// a healthy check cycle, since it doesn't need to know which tier (if any) was
// firing. Each Resolve is a no-op (no recovery notification) when its key isn't
// active, so calling this every cycle is cheap.
func (a *Alerter) ResolveService(ctx context.Context, service string) {
	for _, key := range serviceResolveKeys(service) {
		a.Resolve(ctx, key)
	}
}

// ResolveServiceExcept clears the sibling tiers for a service when it fires at
// keepSeverity, so a critical→warn (or warn→error) transition without an
// intervening healthy cycle never leaves the previous, now-superseded alert
// stuck open.
func (a *Alerter) ResolveServiceExcept(ctx context.Context, service, keepSeverity string) {
	for _, key := range serviceResolveKeysExcept(service, keepSeverity) {
		a.Resolve(ctx, key)
	}
}

// sendEmail sends an alert via the local Postfix on port 25.
func (a *Alerter) sendEmail(severity, service, message, suggestedAction string) {
	from := fmt.Sprintf("vectis@%s", a.hostname)
	subject := fmt.Sprintf("[Vectis %s] %s — %s", severity, service, a.hostname)

	body := fmt.Sprintf(
		"Severity:  %s\nService:   %s\nHostname:  %s\nTime:      %s\n\n%s\n\nSuggested action: %s\n",
		severity, service, a.hostname,
		time.Now().UTC().Format(time.RFC3339),
		message, suggestedAction,
	)

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s",
		from,
		strings.Join(a.emailCfg.Recipients, ", "),
		subject,
		time.Now().UTC().Format(time.RFC1123Z),
		body,
	)

	if err := sendMailWithTimeout(a.emailCfg.SMTPHost, from, a.emailCfg.Recipients, []byte(msg), emailSendTimeout); err != nil {
		a.logger.Error("failed to send alert email",
			"error", err,
			"recipients", a.emailCfg.Recipients,
		)
	}
}

// sendMailWithTimeout is a deadline-bounded replacement for smtp.SendMail (which
// has no timeout). The monitor dispatches alert email inline on its single loop
// goroutine, so a hung SMTP server must not be able to block the exchange
// indefinitely. Postfix on the internal network needs no auth/TLS, so this is a
// plain unauthenticated submission with a hard deadline over the whole session.
func sendMailWithTimeout(addr, from string, to []string, msg []byte, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return fmt.Errorf("dial %s: %w", addr, err)
	}
	// Bound every subsequent read/write on the connection to the same deadline.
	if err := conn.SetDeadline(deadline); err != nil {
		_ = conn.Close()
		return fmt.Errorf("set deadline: %w", err)
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	c, err := smtp.NewClient(conn, host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp handshake: %w", err)
	}
	defer c.Close()

	if err := c.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM: %w", err)
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return fmt.Errorf("RCPT TO %s: %w", rcpt, err)
		}
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("DATA: %w", err)
	}
	if _, err := w.Write(msg); err != nil {
		return fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("close body: %w", err)
	}
	return c.Quit()
}

// sendWebhook POSTs the alert payload to the configured webhook URL.
func (a *Alerter) sendWebhook(ctx context.Context, severity, service, message, suggestedAction string) {
	payload := webhookPayload{
		Severity:        severity,
		Service:         service,
		Message:         message,
		Timestamp:       time.Now().UTC().Format(time.RFC3339),
		Hostname:        a.hostname,
		ActionTaken:     "Alert sent. No automated recovery for runtime failures.",
		SuggestedAction: suggestedAction,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		a.logger.Error("failed to marshal webhook payload", "error", err)
		return
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.webhookCfg.URL, bytes.NewReader(data))
	if err != nil {
		a.logger.Error("failed to create webhook request", "error", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		a.logger.Error("failed to send webhook alert", "error", err, "url", a.webhookCfg.URL)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		a.logger.Error("webhook returned non-success status",
			"status", resp.StatusCode,
			"url", a.webhookCfg.URL,
		)
	}
}

// suggestAction returns a human-readable suggestion for the given service.
func suggestAction(service string) string {
	// container-<svc> alerts (checkContainerHealth) are about the container being
	// down/unreachable; point at the underlying service's logs.
	if rest, ok := strings.CutPrefix(service, "container-"); ok {
		return "Check container status and logs: vectis logs " + rest
	}
	switch service {
	case "disk-postgres":
		return "Free disk space or expand the Postgres data volume"
	case "postfix":
		return "Check logs: vectis logs postfix"
	case "dovecot":
		return "Check logs: vectis logs dovecot"
	case "rspamd":
		return "Check logs: vectis logs rspamd"
	case "clamav":
		return "Check logs: vectis logs clamav"
	case "postgres":
		return "Check database status and connection pool"
	case "valkey":
		return "Check Valkey status: docker compose exec valkey valkey-cli PING"
	case "disk":
		return "Free disk space or expand volume"
	case "queue":
		return "Check mail queue: docker exec vectis-postfix postqueue -p"
	case "tls":
		return "Check TLS certificate and renewal: vectis tls status"
	case "backup", "backup-run":
		return "Check backup status and logs: vectis backup list; vectis logs api"
	default:
		return "Check service logs: vectis logs " + service
	}
}
