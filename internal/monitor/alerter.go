package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/smtp"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/repository"
)

const dedupWindow = 15 * time.Minute

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
	dedupKey := service + ":" + strings.ToLower(severity)

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

	err := smtp.SendMail(a.emailCfg.SMTPHost, nil, from, a.emailCfg.Recipients, []byte(msg))
	if err != nil {
		a.logger.Error("failed to send alert email",
			"error", err,
			"recipients", a.emailCfg.Recipients,
		)
	}
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
	switch service {
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
