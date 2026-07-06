package api

import (
	"context"
	"testing"
)

func TestValidateWebhookURL(t *testing.T) {
	ctx := context.Background()

	// Rejected: bad scheme / SSRF targets given as IP literals (no DNS needed).
	rejected := []string{
		"",
		"not-a-url",
		"http://example.com/hook",        // must be https
		"ftp://example.com",              // must be https
		"https://localhost/hook",         // localhost
		"https://127.0.0.1/hook",         // loopback
		"https://[::1]/hook",             // loopback v6
		"https://10.0.0.1/hook",          // RFC1918
		"https://192.168.1.10/hook",      // RFC1918
		"https://169.254.169.254/latest", // cloud metadata
		"https://0.0.0.0/hook",           // unspecified
		"https://100.64.0.1/hook",        // CGNAT — must match the dispatch-time block
		"https://224.0.0.1/hook",         // multicast — must match the dispatch-time block
	}
	for _, u := range rejected {
		if err := validateWebhookURL(ctx, u); err == nil {
			t.Errorf("validateWebhookURL(%q) = nil, want error", u)
		}
	}

	// Accepted: https to public IP literals (hostname cases hit DNS, so we test
	// literals here to keep the unit test hermetic).
	accepted := []string{
		"https://8.8.8.8/hook",
		"https://93.184.216.34/webhooks/vectis",
	}
	for _, u := range accepted {
		if err := validateWebhookURL(ctx, u); err != nil {
			t.Errorf("validateWebhookURL(%q) = %v, want nil", u, err)
		}
	}
}
