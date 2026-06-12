//go:build integration

package internal_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/validonx"
)

// TestEnterpriseLicenseGateE2E proves the our-side half of Enterprise
// fulfilment: when ValidonX resolves an Enterprise license, the FeatureGate
// opens the Enterprise-only endpoints (saml_sso, dsar); when it resolves a Pro
// license, those same gates deny.
//
// It drives the REAL resolve -> cache -> gate chain end to end against a stub
// ValidonX server. Nothing is pre-seeded into the cache: the first gate check
// is a cache miss that triggers a live /licensing/resolve call, whose result
// is cached and then consulted by the gate. This is the closest automated
// proxy for "a real Enterprise license is activated and the gates open".
//
// The feature STRINGS asserted here are the wire contract ValidonX must emit
// (locked separately by validonx.TestEnterpriseFeatureWireContract). A mismatch
// (e.g. Vx emitting "saml" instead of "saml_sso") would silently leave a paid
// Enterprise customer locked out — this test fails loudly if the chain breaks.
func TestEnterpriseLicenseGateE2E(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool := licGatePool(t, ctx, logger)
	defer pool.Close()

	proFeatures := []string{
		validonx.FeatureBasicMail,
		validonx.FeatureAnalytics, validonx.FeatureOIDCSSO, validonx.FeatureCustomBranding,
		validonx.FeatureAdvancedSpam, validonx.FeaturePrioritySupport,
	}
	enterpriseFeatures := append(append([]string{}, proFeatures...),
		validonx.FeatureSAMLSSO, validonx.FeatureDeliverability, validonx.FeatureSLA, validonx.FeatureDSAR,
	)

	t.Run("enterprise_license_opens_saml_and_dsar", func(t *testing.T) {
		srv := licStubResolve(t, "active", enterpriseFeatures)
		gate, tenantID := licConfiguredGate(t, pool, srv.URL, "e2e-enterprise-tenant", logger)
		licResetCache(t, ctx, gate, tenantID)

		if tier, err := gate.ResolveTier(ctx); err != nil {
			t.Fatalf("ResolveTier: %v", err)
		} else if tier != validonx.TierEnterprise {
			t.Errorf("tier = %q, want %q", tier, validonx.TierEnterprise)
		}

		if !gate.HasFeature(ctx, validonx.FeatureSAMLSSO) {
			t.Error("saml_sso must be available on an Enterprise license")
		}
		if !gate.HasFeature(ctx, validonx.FeatureDSAR) {
			t.Error("dsar must be available on an Enterprise license")
		}

		// SAML login uses the browser gate; DSAR export uses the API gate.
		licAssertGate(t, gate.FeatureGateBrowser(validonx.FeatureSAMLSSO, "SAML single sign-on", "https://vectismail.com/pricing/"), true)
		licAssertGate(t, gate.FeatureGate(validonx.FeatureDSAR), true)
	})

	t.Run("pro_license_denies_saml_and_dsar", func(t *testing.T) {
		srv := licStubResolve(t, "active", proFeatures)
		gate, tenantID := licConfiguredGate(t, pool, srv.URL, "e2e-pro-tenant", logger)
		licResetCache(t, ctx, gate, tenantID)

		if tier, err := gate.ResolveTier(ctx); err != nil {
			t.Fatalf("ResolveTier: %v", err)
		} else if tier != validonx.TierPro {
			t.Errorf("tier = %q, want %q", tier, validonx.TierPro)
		}

		if gate.HasFeature(ctx, validonx.FeatureSAMLSSO) {
			t.Error("saml_sso must be denied on a Pro license")
		}
		if gate.HasFeature(ctx, validonx.FeatureDSAR) {
			t.Error("dsar must be denied on a Pro license")
		}

		licAssertGate(t, gate.FeatureGateBrowser(validonx.FeatureSAMLSSO, "SAML single sign-on", "https://vectismail.com/pricing/"), false)
		licAssertGate(t, gate.FeatureGate(validonx.FeatureDSAR), false)
	})
}

// licGatePool connects to the CI Postgres and runs migrations (creating the
// validonx_cache table the gate reads). Mirrors integration_test.go.
func licGatePool(t *testing.T, ctx context.Context, logger *slog.Logger) *pgxpool.Pool {
	t.Helper()
	dbCfg := database.Config{
		Host:     envOr("VECTIS_TEST_PG_HOST", "127.0.0.1"),
		Port:     envOrInt("VECTIS_TEST_PG_PORT", 5432),
		Name:     envOr("VECTIS_TEST_PG_DB", "vectis"),
		User:     envOr("VECTIS_TEST_PG_USER", "postgres"),
		Password: envOr("VECTIS_TEST_PG_PASSWORD", "vectis_dev_super"),
	}
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	if err := database.RunMigrations(dbCfg.DSN(), logger); err != nil {
		t.Fatalf("run migrations: %v", err)
	}
	return pool
}

// licStubResolve stands in for ValidonX, answering the licensing-resolve
// endpoint with the given status + feature set. It also asserts the request
// CONTRACT (method, path, X-API-Key auth, and license_key in the body) so the
// E2E fails if the client ever regresses its call shape — a wrong verb, a
// dropped auth header, or a missing license_key would all fail against the real
// ValidonX, and must fail here too. Assertions use t.Error (safe from the
// handler goroutine) plus an error status so the gate call surfaces the failure.
func licStubResolve(t *testing.T, status string, features []string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("resolve called with method %s, want POST", r.Method)
			http.Error(w, "bad method", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.Path != "/api/v1/integration/licensing/resolve" {
			t.Errorf("unexpected resolve path %q", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		if r.Header.Get("X-API-Key") == "" {
			t.Error("resolve request missing X-API-Key header")
			http.Error(w, "missing api key", http.StatusUnauthorized)
			return
		}
		var body struct {
			LicenseKey string   `json:"license_key"`
			Features   []string `json:"features"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode resolve body: %v", err)
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		if body.LicenseKey == "" {
			t.Error("resolve request missing license_key in body")
			http.Error(w, "missing license_key", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"data": map[string]any{
				"valid":                true,
				"status":               status,
				"allowed_features":     features,
				"grace_period_ends_at": nil,
				"expires_at":           nil,
			},
			"meta": map[string]any{"request_id": "e2e", "api_version": "1"},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// licConfiguredGate builds a FeatureGateService whose client points at baseURL
// and whose tenant is tenantID, backed by the real validonx_cache table.
func licConfiguredGate(t *testing.T, pool *pgxpool.Pool, baseURL, tenantID string, logger *slog.Logger) (*validonx.FeatureGateService, string) {
	t.Helper()
	client := validonx.NewClient(&config.ValidonXSecrets{
		BaseURL:    baseURL,
		ServiceKey: "e2e-service-key",
		TenantID:   tenantID,
		LicenseKey: "e2e-license-key",
	}, logger)
	if !client.Configured() {
		t.Fatal("validonx client not configured")
	}
	return validonx.NewFeatureGateService(client, pool, logger), tenantID
}

// licResetCache clears any cached row for the tenant before and after the
// subtest, so runs are independent of each other and of prior CI runs. It fails
// loudly on a clear error: a DeleteCached failure means schema drift or DB
// connectivity trouble, which would otherwise let the test pass/fail for the
// wrong reasons.
func licResetCache(t *testing.T, ctx context.Context, gate *validonx.FeatureGateService, tenantID string) {
	t.Helper()
	c := gate.Cache()
	if c == nil {
		t.Fatal("feature gate has no cache (nil DB pool) — cannot run the gate E2E")
	}
	if err := c.DeleteCached(ctx, tenantID); err != nil {
		t.Fatalf("clear cache for tenant %q: %v", tenantID, err)
	}
	t.Cleanup(func() {
		if err := c.DeleteCached(ctx, tenantID); err != nil {
			t.Errorf("cleanup cache for tenant %q: %v", tenantID, err)
		}
	})
}

// licAssertGate runs a request through the middleware and asserts allow (next
// called) or deny (next not called, 403). Accept: application/json forces the
// JSON branch so both the API gate and the browser gate deny with 403.
func licAssertGate(t *testing.T, mw func(http.Handler) http.Handler, wantAllow bool) {
	t.Helper()
	called := false
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	req := httptest.NewRequest(http.MethodGet, "/gated", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if wantAllow {
		if !called {
			t.Errorf("gate should ALLOW: next handler not called (status %d)", rec.Code)
		}
		return
	}
	if called {
		t.Error("gate should DENY: next handler was called")
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("denied gate status = %d, want 403", rec.Code)
	}
}
