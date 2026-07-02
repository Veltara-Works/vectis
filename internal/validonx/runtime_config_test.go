package validonx

import (
	"context"
	"testing"

	"github.com/Veltara-Works/vectis/internal/config"
)

// F-R2: an install configured with a service_key but no explicit base_url must
// resolve against ValidonX's DefaultBaseURL, not silently drop to Free. The
// previous guard ordered the IsConfigured() check (which itself requires a
// non-empty BaseURL) before the fallback, making the fallback dead code — a
// paying service_key-only customer lost their Pro/Enterprise entitlement.
func TestLoadRuntimeConfigServiceKeyOnlyGetsDefaultBaseURL(t *testing.T) {
	// db=nil → secrets.yaml-only path (no DB row).
	cfg, err := LoadRuntimeConfig(context.Background(), nil, &config.ValidonXSecrets{
		ServiceKey: "svc_live_abc123",
	})
	if err != nil {
		t.Fatalf("LoadRuntimeConfig: %v", err)
	}
	if cfg.BaseURL != DefaultBaseURL {
		t.Errorf("service_key-only install BaseURL = %q, want DefaultBaseURL %q", cfg.BaseURL, DefaultBaseURL)
	}
	if !cfg.IsConfigured() {
		t.Error("service_key-only install should be Configured (non-Free) once the default base_url is applied")
	}
}

// An explicit base_url is never overridden by the default fallback.
func TestLoadRuntimeConfigExplicitBaseURLPreserved(t *testing.T) {
	cfg, err := LoadRuntimeConfig(context.Background(), nil, &config.ValidonXSecrets{
		ServiceKey: "svc_live_abc123",
		BaseURL:    "https://validonx.example.test",
	})
	if err != nil {
		t.Fatalf("LoadRuntimeConfig: %v", err)
	}
	if cfg.BaseURL != "https://validonx.example.test" {
		t.Errorf("explicit BaseURL overwritten: got %q", cfg.BaseURL)
	}
}

// A wholly empty config stays Free (no service_key → no default base_url, not
// Configured). The fallback must not manufacture a licensed-looking config.
func TestLoadRuntimeConfigEmptyStaysFree(t *testing.T) {
	cfg, err := LoadRuntimeConfig(context.Background(), nil, &config.ValidonXSecrets{})
	if err != nil {
		t.Fatalf("LoadRuntimeConfig: %v", err)
	}
	if cfg.BaseURL != "" {
		t.Errorf("empty config should not get a base_url, got %q", cfg.BaseURL)
	}
	if cfg.IsConfigured() {
		t.Error("empty config must not be Configured (should be Free)")
	}
}
