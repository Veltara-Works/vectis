package monitor

import (
	"io"
	"log/slog"
	"testing"

	"github.com/Veltara-Works/vectis/internal/config"
)

// mustLogger returns a discard logger — we don't need to inspect output
// for these structural tests.
func mustLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestAlerter_EmailReady verifies the gate logic that prevents the
// alerter from dialling an empty SMTPHost or sending to zero recipients.
// Before rc25 the alerter hard-coded 127.0.0.1:25 and silently failed on
// every fresh install — this test pins the new gate so a future refactor
// can't accidentally reintroduce the same failure mode.
func TestAlerter_EmailReady(t *testing.T) {
	tests := []struct {
		name   string
		cfg    config.AlertEmailConfig
		wantOK bool
	}{
		{
			name:   "disabled → not ready",
			cfg:    config.AlertEmailConfig{Enabled: false, SMTPHost: "vectis-postfix:25", Recipients: []string{"a@b.com"}},
			wantOK: false,
		},
		{
			name:   "enabled but no SMTPHost → not ready (the rc25 regression we're pinning)",
			cfg:    config.AlertEmailConfig{Enabled: true, SMTPHost: "", Recipients: []string{"a@b.com"}},
			wantOK: false,
		},
		{
			name:   "enabled but no recipients → not ready",
			cfg:    config.AlertEmailConfig{Enabled: true, SMTPHost: "vectis-postfix:25", Recipients: nil},
			wantOK: false,
		},
		{
			name:   "fully configured → ready",
			cfg:    config.AlertEmailConfig{Enabled: true, SMTPHost: "vectis-postfix:25", Recipients: []string{"a@b.com"}},
			wantOK: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := NewAlerter(nil, tc.cfg, config.AlertWebhookConfig{}, "mail.example.com", mustLogger())
			if got := a.emailReady(); got != tc.wantOK {
				t.Errorf("emailReady() = %v, want %v", got, tc.wantOK)
			}
		})
	}
}
