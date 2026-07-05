package mail

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"syscall"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

const (
	maxRetries      = 5
	webhookTimeout  = 10 * time.Second
	retryInterval   = 30 * time.Second // poll for pending retries
)

// WebhookEvent is the payload POSTed to webhook endpoints.
type WebhookEvent struct {
	ID        string         `json:"id"`
	Event     string         `json:"event"`      // mail.sent, mail.delivered, mail.bounced, etc.
	Timestamp string         `json:"timestamp"`
	Data      map[string]any `json:"data"`
}

// WebhookDispatcher delivers webhook events to configured endpoints.
type WebhookDispatcher struct {
	webhooks *repository.WebhookRepo
	logger   *slog.Logger
	client   *http.Client
	stopCh   chan struct{}
}

// NewWebhookDispatcher creates a new webhook dispatcher.
func NewWebhookDispatcher(webhooks *repository.WebhookRepo, logger *slog.Logger) *WebhookDispatcher {
	return &WebhookDispatcher{
		webhooks: webhooks,
		logger:   logger,
		client: &http.Client{
			Timeout: webhookTimeout,
			// SSRF guard (MAIL-2): block connections to non-public addresses at
			// dial time. Because Control runs after DNS resolution with the
			// concrete IP, this catches DNS rebinding and redirect-to-internal —
			// which the create-time URL check cannot. Redirects re-dial through
			// the same guard, so an internal redirect target is refused too.
			Transport: &http.Transport{
				DialContext: (&net.Dialer{
					Timeout: webhookTimeout,
					Control: blockPrivateDial,
				}).DialContext,
			},
			CheckRedirect: func(_ *http.Request, via []*http.Request) error {
				if len(via) >= 3 {
					return fmt.Errorf("stopped after 3 redirects")
				}
				return nil
			},
		},
		stopCh: make(chan struct{}),
	}
}

// blockPrivateDial is a net.Dialer.Control hook that refuses to connect to
// non-public addresses. It runs after DNS resolution with the concrete IP:port
// about to be dialed, so it defends the dispatcher against SSRF even via DNS
// rebinding or an HTTP redirect to an internal host (MAIL-2).
func blockPrivateDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("webhook dial: invalid address %q", address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("webhook dial: non-IP address %q", host)
	}
	if isBlockedWebhookIP(ip) {
		return fmt.Errorf("webhook dial to %s blocked (private/loopback/link-local)", ip)
	}
	return nil
}

// isBlockedWebhookIP reports whether an IP must never be a webhook target —
// loopback, RFC1918 private, link-local (incl. cloud-metadata 169.254.169.254),
// CGNAT (RFC 6598, not covered by IsPrivate), unspecified, or multicast.
func isBlockedWebhookIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsInterfaceLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// 100.64.0.0/10 — CGNAT, not flagged by IsPrivate.
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return false
}

// Start begins the retry worker loop.
func (d *WebhookDispatcher) Start() {
	d.logger.Info("starting webhook dispatcher", "retry_interval", retryInterval)
	go d.retryLoop()
}

// Stop signals the retry loop to stop.
func (d *WebhookDispatcher) Stop() {
	d.logger.Info("stopping webhook dispatcher")
	close(d.stopCh)
}

// Dispatch queues and immediately attempts delivery of a webhook event
// to all matching webhooks for the given domain.
func (d *WebhookDispatcher) Dispatch(ctx context.Context, domainID string, event WebhookEvent) {
	webhooks, err := d.webhooks.ListByDomain(ctx, domainID)
	if err != nil {
		d.logger.Error("list webhooks for dispatch failed", "error", err, "domain_id", domainID)
		return
	}

	payload, err := json.Marshal(event)
	if err != nil {
		d.logger.Error("marshal webhook event failed", "error", err)
		return
	}

	for _, wh := range webhooks {
		if !subscribedTo(wh.Events, event.Event) {
			continue
		}

		deliveryID, err := d.webhooks.CreateDelivery(ctx, wh.ID, event.Event, payload)
		if err != nil {
			d.logger.Error("create webhook delivery failed", "error", err, "webhook_id", wh.ID)
			continue
		}

		// Attempt immediate delivery in background.
		go d.deliver(wh, deliveryID, payload, 1)
	}
}

// deliver attempts to POST the payload to the webhook URL.
func (d *WebhookDispatcher) deliver(wh repository.Webhook, deliveryID string, payload []byte, attempt int) {
	ctx, cancel := context.WithTimeout(context.Background(), webhookTimeout)
	defer cancel()

	// Sign payload with HMAC-SHA256.
	signature := signPayload(payload, wh.Secret)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(payload))
	if err != nil {
		d.logger.Error("build webhook request failed", "error", err, "delivery_id", deliveryID)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Vectis-Webhook/1.0")
	req.Header.Set("X-Vectis-Signature", signature)
	req.Header.Set("X-Vectis-Delivery", deliveryID)

	resp, err := d.client.Do(req)
	if err != nil {
		d.scheduleRetry(deliveryID, 0, err.Error(), attempt)
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	respStr := string(body)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if err := d.webhooks.MarkDelivered(context.Background(), deliveryID, resp.StatusCode, respStr); err != nil {
			d.logger.Error("mark delivered failed", "error", err, "delivery_id", deliveryID)
		}
		return
	}

	d.scheduleRetry(deliveryID, resp.StatusCode, respStr, attempt)
}

func (d *WebhookDispatcher) scheduleRetry(deliveryID string, statusCode int, response string, attempt int) {
	ctx := context.Background()
	if attempt >= maxRetries {
		d.webhooks.MarkFailed(ctx, deliveryID, statusCode, response, nil)
		d.logger.Warn("webhook delivery failed permanently",
			"delivery_id", deliveryID, "attempts", attempt, "status", statusCode)
		return
	}

	// Exponential backoff: 30s, 2m, 8m, 32m, ~2h.
	delay := time.Duration(1<<uint(attempt)) * 30 * time.Second
	nextRetry := time.Now().UTC().Add(delay)

	d.webhooks.MarkFailed(ctx, deliveryID, statusCode, response, &nextRetry)
	d.logger.Debug("webhook delivery scheduled for retry",
		"delivery_id", deliveryID, "attempt", attempt, "next_retry", nextRetry)
}

// retryLoop periodically checks for pending webhook deliveries and retries them.
func (d *WebhookDispatcher) retryLoop() {
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			d.processRetries()
		}
	}
}

func (d *WebhookDispatcher) processRetries() {
	ctx := context.Background()
	deliveries, err := d.webhooks.ListPendingRetries(ctx, 50)
	if err != nil {
		d.logger.Error("list pending retries failed", "error", err)
		return
	}

	for _, del := range deliveries {
		wh, err := d.webhooks.GetByID(ctx, del.WebhookID)
		if err != nil || wh == nil {
			continue
		}
		go d.deliver(*wh, del.ID, del.Payload, del.Attempt)
	}
}

func signPayload(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return hex.EncodeToString(mac.Sum(nil))
}

func subscribedTo(events []string, eventType string) bool {
	for _, e := range events {
		if e == eventType || e == "*" {
			return true
		}
	}
	return false
}
