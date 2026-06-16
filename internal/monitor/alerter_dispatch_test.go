package monitor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/config"
)

// TestSuggestAction covers the per-service remediation hint, including the
// default branch that interpolates an unknown service name.
func TestSuggestAction(t *testing.T) {
	tests := []struct {
		service string
		wantSub string // substring the hint must contain
	}{
		{"postfix", "vectis logs postfix"},
		{"dovecot", "vectis logs dovecot"},
		{"rspamd", "vectis logs rspamd"},
		{"clamav", "vectis logs clamav"},
		{"postgres", "connection pool"},
		{"valkey", "valkey-cli PING"},
		{"disk", "disk space"},
		{"queue", "postqueue -p"},
		{"tls", "vectis tls status"},
		{"mystery", "vectis logs mystery"}, // default branch interpolates the name
	}
	for _, tt := range tests {
		t.Run(tt.service, func(t *testing.T) {
			got := suggestAction(tt.service)
			if !strings.Contains(got, tt.wantSub) {
				t.Errorf("suggestAction(%q) = %q, want substring %q", tt.service, got, tt.wantSub)
			}
		})
	}
}

// TestSendWebhook drives the webhook dispatch path against an httptest server,
// asserting the method, content-type, and JSON payload shape. sendWebhook does
// not touch the alert repository, so a nil alerts repo is safe here.
func TestSendWebhook(t *testing.T) {
	type capture struct {
		method      string
		contentType string
		payload     webhookPayload
	}
	gotCh := make(chan capture, 1)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var p webhookPayload
		_ = json.Unmarshal(body, &p)
		gotCh <- capture{method: r.Method, contentType: r.Header.Get("Content-Type"), payload: p}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	a := &Alerter{
		webhookCfg: config.AlertWebhookConfig{Enabled: true, URL: srv.URL},
		hostname:   "test-host",
		logger:     mustLogger(),
	}
	a.sendWebhook(context.Background(), "WARN", "disk", "Disk usage at 85%", "Free disk space")

	// Receive with a timeout rather than a bare <-gotCh so the test fails fast
	// if sendWebhook returns early (e.g. an unexpected marshal/request error)
	// instead of hanging until the suite times out.
	var got capture
	select {
	case got = <-gotCh:
	case <-time.After(2 * time.Second):
		t.Fatal("webhook handler was not called within 2s")
	}
	if got.method != http.MethodPost {
		t.Errorf("method = %q, want POST", got.method)
	}
	if got.contentType != "application/json" {
		t.Errorf("content-type = %q, want application/json", got.contentType)
	}
	if got.payload.Severity != "WARN" {
		t.Errorf("payload.Severity = %q, want WARN", got.payload.Severity)
	}
	if got.payload.Service != "disk" {
		t.Errorf("payload.Service = %q, want disk", got.payload.Service)
	}
	if got.payload.Message != "Disk usage at 85%" {
		t.Errorf("payload.Message = %q, want %q", got.payload.Message, "Disk usage at 85%")
	}
	if got.payload.Hostname != "test-host" {
		t.Errorf("payload.Hostname = %q, want test-host", got.payload.Hostname)
	}
	if got.payload.SuggestedAction != "Free disk space" {
		t.Errorf("payload.SuggestedAction = %q, want %q", got.payload.SuggestedAction, "Free disk space")
	}
	if got.payload.Timestamp == "" {
		t.Error("payload.Timestamp is empty")
	}
}
