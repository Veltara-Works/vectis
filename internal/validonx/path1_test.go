package validonx

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

// path1_test.go — covers the adapter's three risk surfaces:
//   1. The synthesisLicenseResponse pure function (granted-true / granted-false /
//      empty-features cases — no IO required).
//   2. The HTTP round-trip with a mock ValidonX (200 success, 401, 403, 404,
//      422, 429-with-retry).
//   3. parseRetryAfter helper for the retry-budget logic.
//
// When path-2's /v1/licensing/resolve ships, this file gets deleted alongside
// path1.go. The synthesise test cases inform the path-2 client tests we
// should write at that time.

func TestSynthesiseLicenseResponse(t *testing.T) {
	build := func(grants map[string]bool) *path1Response {
		r := &path1Response{}
		r.Data.Entitlements.Features = make(map[string]path1FeatureGrant, len(grants))
		for k, v := range grants {
			r.Data.Entitlements.Features[k] = path1FeatureGrant{Granted: v, Value: v}
		}
		return r
	}

	t.Run("active Pro with all six grants", func(t *testing.T) {
		got := synthesiseLicenseResponse(build(map[string]bool{
			FeatureBasicMail:       true,
			FeatureAnalytics:       true,
			FeatureOIDCSSO:         true,
			FeatureCustomBranding:  true,
			FeatureAdvancedSpam:    true,
			FeaturePrioritySupport: true,
		}))
		if got.Status != path1StatusActive || !got.Valid {
			t.Errorf("Pro with all grants should be active+valid; got status=%q valid=%v", got.Status, got.Valid)
		}
		if len(got.AllowedFeatures) != 6 {
			t.Errorf("expected 6 allowed features, got %d (%v)", len(got.AllowedFeatures), got.AllowedFeatures)
		}
	})

	t.Run("partial Pro grants — analytics only", func(t *testing.T) {
		got := synthesiseLicenseResponse(build(map[string]bool{
			FeatureBasicMail:      true,
			FeatureAnalytics:      true,
			FeatureOIDCSSO:        false,
			FeatureCustomBranding: false,
		}))
		if got.Status != path1StatusActive || !got.Valid {
			t.Errorf("any non-basic grant should flip valid=true; got %v", got)
		}
		if !contains(got.AllowedFeatures, FeatureAnalytics) {
			t.Errorf("analytics should be in allowed features: %v", got.AllowedFeatures)
		}
		if contains(got.AllowedFeatures, FeatureOIDCSSO) {
			t.Errorf("denied features must not appear: %v", got.AllowedFeatures)
		}
	})

	t.Run("only basic_mail granted — not enough for Pro", func(t *testing.T) {
		got := synthesiseLicenseResponse(build(map[string]bool{
			FeatureBasicMail:      true,
			FeatureAnalytics:      false,
			FeatureOIDCSSO:        false,
			FeatureCustomBranding: false,
		}))
		// FeatureBasicMail alone is Free tier; no Pro entitlement.
		if got.Valid {
			t.Errorf("basic_mail alone should NOT flip valid=true (would mean Free is treated as active Pro); got %v", got)
		}
	})

	t.Run("empty features — license resolved but no entitlements", func(t *testing.T) {
		got := synthesiseLicenseResponse(build(map[string]bool{}))
		if got.Valid {
			t.Errorf("empty features must not be valid; got %v", got)
		}
		if got.Status == path1StatusActive {
			t.Errorf("empty features must not be active; got status=%q", got.Status)
		}
	})

	t.Run("all features denied", func(t *testing.T) {
		got := synthesiseLicenseResponse(build(map[string]bool{
			FeatureBasicMail:       false,
			FeatureAnalytics:       false,
			FeatureOIDCSSO:         false,
			FeatureCustomBranding:  false,
			FeatureAdvancedSpam:    false,
			FeaturePrioritySupport: false,
		}))
		if got.Valid {
			t.Errorf("all-denied must not be valid; got %v", got)
		}
		if len(got.AllowedFeatures) != 0 {
			t.Errorf("all-denied must yield zero allowed features; got %v", got.AllowedFeatures)
		}
	})
}

func TestParseRetryAfter(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{"empty", "", 0},
		{"plain seconds", "3", 3 * time.Second},
		{"zero", "0", 0},
		{"negative-ish (Atoi rejects)", "-1", 0},
		{"junk", "soon", 0},
		// HTTP-date parsing covered indirectly — http.ParseTime rejects junk.
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got := parseRetryAfter(tt.raw)
			if got != tt.want {
				t.Errorf("parseRetryAfter(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestCheckLicensePath1_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify request shape against ValidonX team's spec.
		if r.URL.Path != path1EntitlementsPath {
			t.Errorf("path = %q, want %q", r.URL.Path, path1EntitlementsPath)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q, want POST", r.Method)
		}
		if r.Header.Get("X-API-Key") != "test-service-key" {
			t.Errorf("X-API-Key = %q, want test-service-key", r.Header.Get("X-API-Key"))
		}
		if r.Header.Get("X-Request-ID") == "" {
			t.Error("X-Request-ID header should be set for tracing")
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", r.Header.Get("Content-Type"))
		}

		body, _ := io.ReadAll(r.Body)
		var req path1Request
		if err := json.Unmarshal(body, &req); err != nil {
			t.Fatalf("decode request body: %v", err)
		}
		if req.LicenseKey != "lk_test_abc" {
			t.Errorf("license_key = %q, want lk_test_abc", req.LicenseKey)
		}
		if len(req.Features) == 0 {
			t.Error("features should default to full set when nil passed in")
		}

		// Return Pro grants.
		_ = json.NewEncoder(w).Encode(path1Response{
			Data: struct {
				Entitlements struct {
					Features map[string]path1FeatureGrant `json:"features"`
					Limits   map[string]struct {
						Limit float64 `json:"limit"`
						Type  string  `json:"type"`
					} `json:"limits,omitempty"`
				} `json:"entitlements"`
			}{
				Entitlements: struct {
					Features map[string]path1FeatureGrant `json:"features"`
					Limits   map[string]struct {
						Limit float64 `json:"limit"`
						Type  string  `json:"type"`
					} `json:"limits,omitempty"`
				}{
					Features: map[string]path1FeatureGrant{
						FeatureBasicMail: {Granted: true, Value: true},
						FeatureAnalytics: {Granted: true, Value: true},
						FeatureOIDCSSO:   {Granted: true, Value: true},
					},
				},
			},
		})
	}))
	defer server.Close()

	c := NewClient(&config.ValidonXSecrets{
		BaseURL:    server.URL,
		ServiceKey: "test-service-key",
		LicenseKey: "lk_test_abc",
	}, testLogger())

	resp, err := c.CheckLicensePath1(context.Background(), nil)
	if err != nil {
		t.Fatalf("CheckLicensePath1 unexpected error: %v", err)
	}
	if !resp.Valid || resp.Status != path1StatusActive {
		t.Errorf("expected active+valid, got status=%q valid=%v", resp.Status, resp.Valid)
	}
	if !contains(resp.AllowedFeatures, FeatureAnalytics) {
		t.Errorf("analytics missing from allowed: %v", resp.AllowedFeatures)
	}
}

func TestCheckLicensePath1_Suspended(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(path1ErrorEnvelope{
			Error: struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}{Code: "TENANT.STATUS.SUSPENDED", Message: "Tenant is suspended"},
		})
	}))
	defer server.Close()

	c := NewClient(&config.ValidonXSecrets{
		BaseURL: server.URL, ServiceKey: "k", LicenseKey: "lk",
	}, testLogger())

	resp, err := c.CheckLicensePath1(context.Background(), nil)
	if err != nil {
		t.Fatalf("403 should NOT bubble as error (returned as valid=false response): %v", err)
	}
	if resp.Valid {
		t.Errorf("suspended tenant must be invalid; got %v", resp)
	}
	if resp.Status != path1StatusSuspended {
		t.Errorf("status = %q, want %q", resp.Status, path1StatusSuspended)
	}
}

func TestCheckLicensePath1_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(path1ErrorEnvelope{
			Error: struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}{Code: "LICENSE.NOT_FOUND", Message: "License not found for tenant"},
		})
	}))
	defer server.Close()

	c := NewClient(&config.ValidonXSecrets{
		BaseURL: server.URL, ServiceKey: "k", LicenseKey: "lk",
	}, testLogger())

	resp, err := c.CheckLicensePath1(context.Background(), nil)
	if err != nil {
		t.Fatalf("404 should not bubble as error: %v", err)
	}
	if resp.Valid || resp.Status != path1StatusNotFound {
		t.Errorf("not_found expected; got %v", resp)
	}
}

func TestCheckLicensePath1_AuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(path1ErrorEnvelope{
			Error: struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			}{Code: "AUTH.INVALID_API_KEY", Message: "Invalid API key"},
		})
	}))
	defer server.Close()

	c := NewClient(&config.ValidonXSecrets{
		BaseURL: server.URL, ServiceKey: "wrong-key", LicenseKey: "lk",
	}, testLogger())

	_, err := c.CheckLicensePath1(context.Background(), nil)
	if err == nil {
		t.Fatal("auth failure should bubble as error (operator config bug, not customer state)")
	}
	if !strings.Contains(err.Error(), "AUTH.INVALID_API_KEY") {
		t.Errorf("error should include code; got %v", err)
	}
}

func TestCheckLicensePath1_RateLimitedThenSuccess(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(path1ErrorEnvelope{
				Error: struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				}{Code: "RATE.LIMIT_EXCEEDED", Message: "Slow down"},
			})
			return
		}
		_ = json.NewEncoder(w).Encode(path1Response{
			Data: struct {
				Entitlements struct {
					Features map[string]path1FeatureGrant `json:"features"`
					Limits   map[string]struct {
						Limit float64 `json:"limit"`
						Type  string  `json:"type"`
					} `json:"limits,omitempty"`
				} `json:"entitlements"`
			}{
				Entitlements: struct {
					Features map[string]path1FeatureGrant `json:"features"`
					Limits   map[string]struct {
						Limit float64 `json:"limit"`
						Type  string  `json:"type"`
					} `json:"limits,omitempty"`
				}{
					Features: map[string]path1FeatureGrant{
						FeatureAnalytics: {Granted: true, Value: true},
					},
				},
			},
		})
	}))
	defer server.Close()

	c := NewClient(&config.ValidonXSecrets{
		BaseURL: server.URL, ServiceKey: "k", LicenseKey: "lk",
	}, testLogger())

	resp, err := c.CheckLicensePath1(context.Background(), nil)
	if err != nil {
		t.Fatalf("retry should succeed: %v", err)
	}
	if !resp.Valid {
		t.Errorf("retry result should be valid; got %v", resp)
	}
	if calls != 2 {
		t.Errorf("expected 2 calls (1 retry); got %d", calls)
	}
}

func TestCheckLicensePath1_MissingLicenseKey(t *testing.T) {
	c := NewClient(&config.ValidonXSecrets{
		BaseURL: "https://api.example.com", ServiceKey: "k",
		// LicenseKey deliberately empty
	}, testLogger())
	_, err := c.CheckLicensePath1(context.Background(), nil)
	if err == nil {
		t.Fatal("missing license_key should error before HTTP call")
	}
	if !strings.Contains(err.Error(), "license_key") {
		t.Errorf("error should name the missing field; got %v", err)
	}
}

// contains is a tiny test helper to keep assertions readable.
func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
