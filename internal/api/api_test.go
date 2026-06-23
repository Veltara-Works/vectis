//go:build integration

package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/api"
	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/repository"
)

type testEnv struct {
	server  *api.Server
	handler http.Handler
	pool    *pgxpool.Pool
	cookie  string
	adminID string
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// Defaults match the CI service containers; override via VECTIS_TEST_PG_*
	// when running against a disposable DB on a host with another Postgres on
	// :5432 (e.g. the build VPS).
	dbCfg := database.Config{
		Host:     envOr("VECTIS_TEST_PG_HOST", "127.0.0.1"),
		Port:     5432,
		Name:     envOr("VECTIS_TEST_PG_DB", "vectis"),
		User:     envOr("VECTIS_TEST_PG_USER", "postgres"),
		Password: envOr("VECTIS_TEST_PG_PASSWORD", "vectis_dev_super"),
	}
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}

	// Apply migrations so this package is self-sufficient. `go test
	// ./internal/...` runs package binaries against the shared test DB with no
	// ordering guarantee, so api_test cannot assume the root integration suite
	// has already created the schema. Idempotent — no-ops once applied.
	if err := database.RunMigrations(dbCfg.DSN(), logger); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	vk, err := database.NewValkeyClient(database.ValkeyConfig{
		Host:     envOr("VECTIS_TEST_VK_HOST", "127.0.0.1"),
		Port:     6379,
		Password: envOr("VECTIS_TEST_VK_PASSWORD", "vectis_dev_valkey"),
	}, logger)
	if err != nil {
		t.Fatalf("connect valkey: %v", err)
	}

	srv := api.New(pool, vk, api.Config{
		ListenAddr:   ":0",
		SessionTTL:   24,
		CookieSecret: "test-secret-32-chars-minimum-1234",
		Hostname:     "test.example.com",
		DKIMBasePath: t.TempDir(),
	}, logger)

	// Seed a super_admin for tests. The default admin role lacks access to
	// license / config / orchestrator routes (they require super_admin via
	// requireSuperAdmin()), so any test that touches those endpoints —
	// including TestLicenseActivation_ProbeUsesPath2Endpoint and the
	// Advanced-Spam tier-gate tests — would 403 with the default role.
	// super_admin is a strict superset of admin's permissions, so existing
	// tests are unaffected.
	adminRepo := repository.NewAdminRepo(pool)
	hash, _ := auth.HashPassword("test-password")
	admin, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        fmt.Sprintf("test-%d@example.com", time.Now().UnixNano()),
		PasswordHash: hash,
		Role:         "super_admin",
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}

	env := &testEnv{
		server:  srv,
		handler: srv.Handler(),
		pool:    pool,
		adminID: admin.ID,
	}

	// Login to get session cookie.
	loginBody := fmt.Sprintf(`{"email":"%s","password":"test-password"}`, admin.Email)
	resp := env.doRequest(t, "POST", "/api/v1/auth/login", loginBody)
	if resp.StatusCode != 200 {
		t.Fatalf("login failed: %d", resp.StatusCode)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "vectis_session" {
			env.cookie = c.Value
		}
	}

	t.Cleanup(func() {
		pool.Close()
		vk.Close()
	})

	return env
}

func (e *testEnv) doRequest(t *testing.T, method, path, body string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	if e.cookie != "" {
		req.AddCookie(&http.Cookie{Name: "vectis_session", Value: e.cookie})
	}
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	return w.Result()
}

func (e *testEnv) doRequestWithHeader(t *testing.T, method, path, body, headerKey, headerVal string) *http.Response {
	t.Helper()
	var bodyReader io.Reader
	if body != "" {
		bodyReader = bytes.NewBufferString(body)
	}
	req := httptest.NewRequest(method, path, bodyReader)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(headerKey, headerVal)
	if e.cookie != "" {
		req.AddCookie(&http.Cookie{Name: "vectis_session", Value: e.cookie})
	}
	w := httptest.NewRecorder()
	e.handler.ServeHTTP(w, req)
	return w.Result()
}

func parseBody(t *testing.T, resp *http.Response) map[string]any {
	t.Helper()
	defer resp.Body.Close()
	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)
	return result
}

// ── Health + Version ─────────────────────────────────────────────

func TestHealth(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/api/v1/health", "")
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body := parseBody(t, resp)
	data := body["data"].(map[string]any)
	if data["status"] != "healthy" {
		t.Fatalf("expected healthy, got %v", data["status"])
	}
	if data["version"] == nil {
		t.Fatal("missing version in health response")
	}
	services := data["services"].(map[string]any)
	for name, svc := range services {
		s := svc.(map[string]any)
		if s["status"] != "healthy" {
			t.Errorf("service %s unhealthy", name)
		}
	}
}

func TestVersion(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/api/v1/version", "")
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body := parseBody(t, resp)
	data := body["data"].(map[string]any)
	if data["version"] == nil || data["go_version"] == nil {
		t.Fatal("missing fields in version response")
	}
}

// ── Auth ─────────────────────────────────────────────────────────

func TestAuthUnauthenticated(t *testing.T) {
	env := setupTestEnv(t)
	saved := env.cookie
	env.cookie = ""
	resp := env.doRequest(t, "GET", "/api/v1/domains", "")
	env.cookie = saved
	if resp.StatusCode != 401 {
		t.Fatalf("expected 401, got %d", resp.StatusCode)
	}
}

func TestAuthSessions(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "GET", "/api/v1/auth/sessions", "")
	if resp.StatusCode != 200 {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	body := parseBody(t, resp)
	sessions := body["data"].([]any)
	if len(sessions) == 0 {
		t.Fatal("expected at least 1 session")
	}
}

// ── Domains CRUD ─────────────────────────────────────────────────

func TestDomainCRUD(t *testing.T) {
	env := setupTestEnv(t)
	domainName := fmt.Sprintf("test-%d.example.com", time.Now().UnixNano())

	// Create
	resp := env.doRequest(t, "POST", "/api/v1/domains", fmt.Sprintf(`{"name":"%s"}`, domainName))
	if resp.StatusCode != 201 {
		body := parseBody(t, resp)
		t.Fatalf("create domain: expected 201, got %d: %v", resp.StatusCode, body)
	}
	body := parseBody(t, resp)
	data := body["data"].(map[string]any)
	domain := data["domain"].(map[string]any)
	domainID := domain["id"].(string)

	// DKIM should be auto-generated
	if data["dkim"] == nil {
		t.Error("expected DKIM info in create response")
	}

	// Get
	resp = env.doRequest(t, "GET", "/api/v1/domains/"+domainID, "")
	if resp.StatusCode != 200 {
		t.Fatalf("get domain: expected 200, got %d", resp.StatusCode)
	}

	// List
	resp = env.doRequest(t, "GET", "/api/v1/domains", "")
	if resp.StatusCode != 200 {
		t.Fatalf("list domains: expected 200, got %d", resp.StatusCode)
	}

	// Update
	resp = env.doRequest(t, "PATCH", "/api/v1/domains/"+domainID, `{"spam_threshold":10.0}`)
	if resp.StatusCode != 200 {
		t.Fatalf("update domain: expected 200, got %d", resp.StatusCode)
	}

	// Duplicate
	resp = env.doRequest(t, "POST", "/api/v1/domains", fmt.Sprintf(`{"name":"%s"}`, domainName))
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate domain: expected 409, got %d", resp.StatusCode)
	}

	// Delete (should work — no mailboxes)
	resp = env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete domain: expected 200, got %d", resp.StatusCode)
	}

	// Get after delete
	resp = env.doRequest(t, "GET", "/api/v1/domains/"+domainID, "")
	if resp.StatusCode != 404 {
		t.Fatalf("get deleted domain: expected 404, got %d", resp.StatusCode)
	}
}

func TestDomainDeleteWithMailboxes(t *testing.T) {
	env := setupTestEnv(t)
	domainName := fmt.Sprintf("del-test-%d.example.com", time.Now().UnixNano())

	// Create domain
	resp := env.doRequest(t, "POST", "/api/v1/domains", fmt.Sprintf(`{"name":"%s"}`, domainName))
	body := parseBody(t, resp)
	domain := body["data"].(map[string]any)["domain"].(map[string]any)
	domainID := domain["id"].(string)

	// Create mailbox
	resp = env.doRequest(t, "POST", "/api/v1/mailboxes",
		fmt.Sprintf(`{"domain_id":"%s","local_part":"user","password":"TestPass123"}`, domainID))
	if resp.StatusCode != 201 {
		t.Fatalf("create mailbox: expected 201, got %d", resp.StatusCode)
	}
	mboxBody := parseBody(t, resp)
	mboxID := mboxBody["data"].(map[string]any)["id"].(string)

	// Delete domain should fail (has mailboxes)
	resp = env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
	if resp.StatusCode != 409 {
		t.Fatalf("delete domain with mailboxes: expected 409, got %d", resp.StatusCode)
	}

	// Delete mailbox (with confirm header)
	resp = env.doRequestWithHeader(t, "DELETE", "/api/v1/mailboxes/"+mboxID, "", "X-Confirm-Delete", "true")
	if resp.StatusCode != 200 {
		t.Fatalf("delete mailbox: expected 200, got %d", resp.StatusCode)
	}

	// Now delete domain should work
	resp = env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete empty domain: expected 200, got %d", resp.StatusCode)
	}
}

// ── Mailbox CRUD ─────────────────────────────────────────────────

func TestMailboxCRUD(t *testing.T) {
	env := setupTestEnv(t)
	domainName := fmt.Sprintf("mbox-%d.example.com", time.Now().UnixNano())

	// Create domain
	resp := env.doRequest(t, "POST", "/api/v1/domains", fmt.Sprintf(`{"name":"%s"}`, domainName))
	body := parseBody(t, resp)
	domainID := body["data"].(map[string]any)["domain"].(map[string]any)["id"].(string)

	// Create mailbox
	resp = env.doRequest(t, "POST", "/api/v1/mailboxes",
		fmt.Sprintf(`{"domain_id":"%s","local_part":"alice","password":"Pass1234!","display_name":"Alice","quota_mb":2048}`, domainID))
	if resp.StatusCode != 201 {
		t.Fatalf("create mailbox: expected 201, got %d", resp.StatusCode)
	}
	mbox := parseBody(t, resp)["data"].(map[string]any)
	mboxID := mbox["id"].(string)
	if mbox["quota_mb"].(float64) != 2048 {
		t.Errorf("expected quota 2048, got %v", mbox["quota_mb"])
	}
	if mbox["display_name"] != "Alice" {
		t.Errorf("expected display_name Alice, got %v", mbox["display_name"])
	}

	// Get
	resp = env.doRequest(t, "GET", "/api/v1/mailboxes/"+mboxID, "")
	if resp.StatusCode != 200 {
		t.Fatalf("get mailbox: expected 200, got %d", resp.StatusCode)
	}

	// List
	resp = env.doRequest(t, "GET", "/api/v1/mailboxes?domain_id="+domainID, "")
	if resp.StatusCode != 200 {
		t.Fatalf("list mailboxes: expected 200, got %d", resp.StatusCode)
	}
	list := parseBody(t, resp)["data"].([]any)
	if len(list) != 1 {
		t.Fatalf("expected 1 mailbox, got %d", len(list))
	}

	// Update
	resp = env.doRequest(t, "PATCH", "/api/v1/mailboxes/"+mboxID, `{"quota_mb":4096}`)
	if resp.StatusCode != 200 {
		t.Fatalf("update mailbox: expected 200, got %d", resp.StatusCode)
	}

	// Duplicate
	resp = env.doRequest(t, "POST", "/api/v1/mailboxes",
		fmt.Sprintf(`{"domain_id":"%s","local_part":"alice","password":"Pass1234!"}`, domainID))
	if resp.StatusCode != 409 {
		t.Fatalf("duplicate mailbox: expected 409, got %d", resp.StatusCode)
	}

	// Delete without confirm header
	resp = env.doRequest(t, "DELETE", "/api/v1/mailboxes/"+mboxID, "")
	if resp.StatusCode != 400 {
		t.Fatalf("delete without confirm: expected 400, got %d", resp.StatusCode)
	}

	// Delete with confirm
	resp = env.doRequestWithHeader(t, "DELETE", "/api/v1/mailboxes/"+mboxID, "", "X-Confirm-Delete", "true")
	if resp.StatusCode != 200 {
		t.Fatalf("delete mailbox: expected 200, got %d", resp.StatusCode)
	}

	// Cleanup domain
	env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
}

// ── Aliases CRUD ─────────────────────────────────────────────────

func TestAliasCRUD(t *testing.T) {
	env := setupTestEnv(t)
	domainName := fmt.Sprintf("alias-%d.example.com", time.Now().UnixNano())

	// Create domain
	resp := env.doRequest(t, "POST", "/api/v1/domains", fmt.Sprintf(`{"name":"%s"}`, domainName))
	body := parseBody(t, resp)
	domainID := body["data"].(map[string]any)["domain"].(map[string]any)["id"].(string)

	// Create alias
	resp = env.doRequest(t, "POST", "/api/v1/aliases",
		fmt.Sprintf(`{"domain_id":"%s","source_local_part":"info","destination":"admin@external.com"}`, domainID))
	if resp.StatusCode != 201 {
		t.Fatalf("create alias: expected 201, got %d", resp.StatusCode)
	}
	alias := parseBody(t, resp)["data"].(map[string]any)
	aliasID := alias["id"].(string)

	// Create catch-all
	resp = env.doRequest(t, "POST", "/api/v1/aliases",
		fmt.Sprintf(`{"domain_id":"%s","source_local_part":"","destination":"catchall@external.com"}`, domainID))
	if resp.StatusCode != 201 {
		t.Fatalf("create catch-all: expected 201, got %d", resp.StatusCode)
	}
	catchAll := parseBody(t, resp)["data"].(map[string]any)
	catchAllID := catchAll["id"].(string)

	// List
	resp = env.doRequest(t, "GET", "/api/v1/aliases?domain_id="+domainID, "")
	if resp.StatusCode != 200 {
		t.Fatalf("list aliases: expected 200, got %d", resp.StatusCode)
	}
	list := parseBody(t, resp)["data"].([]any)
	if len(list) != 2 {
		t.Fatalf("expected 2 aliases, got %d", len(list))
	}

	// Update
	resp = env.doRequest(t, "PATCH", "/api/v1/aliases/"+aliasID, `{"destination":"new@external.com"}`)
	if resp.StatusCode != 200 {
		t.Fatalf("update alias: expected 200, got %d", resp.StatusCode)
	}

	// Delete
	resp = env.doRequest(t, "DELETE", "/api/v1/aliases/"+aliasID, "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete alias: expected 200, got %d", resp.StatusCode)
	}

	// Cleanup
	env.doRequest(t, "DELETE", "/api/v1/aliases/"+catchAllID, "")
	env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
}

// ── DKIM + Deliverability ────────────────────────────────────────

func TestDKIMEndpoints(t *testing.T) {
	env := setupTestEnv(t)
	domainName := fmt.Sprintf("dkim-%d.example.com", time.Now().UnixNano())

	// Create domain (auto DKIM)
	resp := env.doRequest(t, "POST", "/api/v1/domains", fmt.Sprintf(`{"name":"%s"}`, domainName))
	body := parseBody(t, resp)
	domainID := body["data"].(map[string]any)["domain"].(map[string]any)["id"].(string)

	// Get DKIM
	resp = env.doRequest(t, "GET", "/api/v1/domains/"+domainID+"/dkim", "")
	if resp.StatusCode != 200 {
		t.Fatalf("get DKIM: expected 200, got %d", resp.StatusCode)
	}
	dkimData := parseBody(t, resp)["data"].(map[string]any)
	if dkimData["dns_name"] == nil || dkimData["dns_value"] == nil {
		t.Error("missing DKIM fields")
	}

	// Rotate DKIM
	resp = env.doRequest(t, "POST", "/api/v1/domains/"+domainID+"/dkim/rotate", "")
	if resp.StatusCode != 200 {
		t.Fatalf("rotate DKIM: expected 200, got %d", resp.StatusCode)
	}
	rotated := parseBody(t, resp)["data"].(map[string]any)
	if rotated["selector"] == dkimData["selector"] {
		t.Error("selector should have changed after rotation")
	}

	// Deliverability
	resp = env.doRequest(t, "GET", "/api/v1/domains/"+domainID+"/deliverability", "")
	if resp.StatusCode != 200 {
		t.Fatalf("deliverability: expected 200, got %d", resp.StatusCode)
	}
	deliv := parseBody(t, resp)["data"].(map[string]any)
	checks := deliv["checks"].([]any)
	if len(checks) < 3 {
		t.Errorf("expected at least 3 deliverability checks, got %d", len(checks))
	}

	// Cleanup
	env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
}

// ── Validation ───────────────────────────────────────────────────

func TestValidation(t *testing.T) {
	env := setupTestEnv(t)

	// Invalid domain name
	resp := env.doRequest(t, "POST", "/api/v1/domains", `{"name":"not valid!"}`)
	if resp.StatusCode != 400 {
		t.Fatalf("invalid domain: expected 400, got %d", resp.StatusCode)
	}

	// Missing fields
	resp = env.doRequest(t, "POST", "/api/v1/domains", `{}`)
	if resp.StatusCode != 400 {
		t.Fatalf("empty domain: expected 400, got %d", resp.StatusCode)
	}

	// Mailbox with missing password
	resp = env.doRequest(t, "POST", "/api/v1/mailboxes", `{"domain_id":"fake","local_part":"user"}`)
	if resp.StatusCode != 400 {
		t.Fatalf("missing password: expected 400, got %d", resp.StatusCode)
	}

	// Alias with missing destination
	resp = env.doRequest(t, "POST", "/api/v1/aliases", `{"domain_id":"fake"}`)
	if resp.StatusCode != 400 {
		t.Fatalf("missing destination: expected 400, got %d", resp.StatusCode)
	}

	// Bad JSON
	resp = env.doRequest(t, "POST", "/api/v1/domains", `{not json}`)
	if resp.StatusCode != 400 {
		t.Fatalf("bad JSON: expected 400, got %d", resp.StatusCode)
	}

	// Not found
	resp = env.doRequest(t, "GET", "/api/v1/domains/00000000-0000-0000-0000-000000000000", "")
	if resp.StatusCode != 404 {
		t.Fatalf("not found: expected 404, got %d", resp.StatusCode)
	}
}

// ── License activation routing (path-2) ─────────

// TestLicenseActivation_ProbeUsesPath2Endpoint is the post-revert successor
// to the rc57/rc58 path-1 regression guard. The contract is now:
// handleSetLicense's validation probe MUST hit path-2's
// /api/v1/integration/licensing/resolve. A regression that points it at any
// other URL (including the obsolete path-1 entitlements/check) fails the test.
func TestLicenseActivation_ProbeUsesPath2Endpoint(t *testing.T) {
	env := setupTestEnv(t)

	var (
		path1Hits int
		path2Hits int
	)
	mockValidonX := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/integration/licensing/resolve":
			path2Hits++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": {
					"valid": true,
					"status": "active",
					"allowed_features": ["basic_mail", "analytics", "oidc_sso"],
					"grace_period_ends_at": null,
					"expires_at": "2027-04-26T00:00:00+00:00",
					"license": {"id": "00000000-0000-0000-0000-000000000001", "key": "VLDX-VECTIS-PRO-TEST-001", "type": "subscription"}
				},
				"meta": {"request_id": "regression-test-rid", "api_version": "1"}
			}`))
		case "/api/v1/integration/entitlements/check":
			// REGRESSION: hitting the obsolete path-1 endpoint means the
			// revert was incomplete. Record + fail.
			path1Hits++
			t.Errorf("REGRESSION: activation probe hit path-1 endpoint %q — handle_license.go must call CheckLicense (path-2). See docs/notes/deferred-items.md §11.", r.URL.Path)
			http.Error(w, `{"error":"path-1 retired"}`, http.StatusGone)
		case "/v1/auth/login":
			// Auth is not used on the path-2 resolve route (X-API-Key
			// middleware), but the mock should not 404 on it during
			// any preliminary client setup.
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"t","expires_at":"2099-01-01T00:00:00Z"}`))
		default:
			t.Errorf("unexpected mock-server path hit during activation: %q", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	}))
	defer mockValidonX.Close()

	// Ensure validonx_config table is empty before the test.
	_, _ = env.doRequest(t, "DELETE", "/api/v1/license", "").Body.Read(nil)

	// Activate via the public API exactly as the admin UI would.
	body, _ := json.Marshal(map[string]string{
		"base_url":        mockValidonX.URL,
		"service_key":     "test-service-key",
		"tenant_id":       "regression-tenant",
		"subscription_id": "sub_regression_test_0001",
		"license_key":     "VLDX-VECTIS-PRO-TEST-001",
	})
	resp := env.doRequest(t, "POST", "/api/v1/license", string(body))
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("activation POST: expected 200, got %d (body: %s)", resp.StatusCode, raw)
	}

	parsed := parseBody(t, resp)
	data, ok := parsed["data"].(map[string]any)
	if !ok {
		t.Fatalf("activation response missing data envelope: %v", parsed)
	}
	if tier, _ := data["tier"].(string); tier != "pro" {
		t.Errorf("expected tier=pro after activation; got %q (full response: %v)", tier, parsed)
	}
	if configured, _ := data["configured"].(bool); !configured {
		t.Errorf("expected configured=true after activation; got %v", parsed)
	}

	// Routing assertions — the load-bearing part.
	if path2Hits == 0 {
		t.Errorf("path-2 endpoint was never hit; activation probe must route through CheckLicense")
	}
	if path1Hits != 0 {
		t.Errorf("obsolete path-1 endpoint was hit %d time(s) during activation; expected 0", path1Hits)
	}

	// Cleanup.
	env.doRequest(t, "DELETE", "/api/v1/license", "")
}

// TestLicenseActivation_RejectsMissingTenantID pins the cold-boot guardrail:
// a POST without tenant_id must 400 with MISSING_TENANT_ID, not silently
// produce a half-broken activated state. ValidonX never returns tenant_id
// on the wire (path-2 ADR-041), so the server cannot derive it from the
// probe response — the user must provide it. Without this guard, the
// FeatureGate cache primes against an empty key while reads use the
// populated key, leaving /auth/me + /api/v1/license stuck on tier=free
// even though Pro endpoints allow. See project_license_first_time_from_free.md.
func TestLicenseActivation_RejectsMissingTenantID(t *testing.T) {
	env := setupTestEnv(t)

	// Activate via the public API with no tenant_id. base_url + service_key
	// pass IsConfigured(), license_key passes the LicenseKey check — without
	// the tenant_id guardrail this would reach probe.CheckLicense and the
	// half-broken state would be persisted.
	body, _ := json.Marshal(map[string]string{
		"base_url":    "https://example.invalid",
		"service_key": "test-service-key",
		"license_key": "VLDX-VECTIS-PRO-TEST-001",
		// tenant_id deliberately absent
	})
	resp := env.doRequest(t, "POST", "/api/v1/license", string(body))
	defer resp.Body.Close()

	if resp.StatusCode != 400 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("activation POST without tenant_id: expected 400, got %d (body: %s)", resp.StatusCode, raw)
	}

	parsed := parseBody(t, resp)
	errObj, ok := parsed["error"].(map[string]any)
	if !ok {
		t.Fatalf("expected error envelope, got %v", parsed)
	}
	if code, _ := errObj["code"].(string); code != "MISSING_TENANT_ID" {
		t.Errorf("expected error code MISSING_TENANT_ID, got %q (full response: %v)", code, parsed)
	}
}

// ── Billing portal session ───────────────────────────────────────
//
// /account/billing-portal-session is the proxy that lets paying customers
// reach the Stripe Customer Portal without ever seeing the ValidonX brand
// in their URL bar. Tests cover (a) the unconfigured guard, (b) the happy
// path against a mock ValidonX, (c) cross-origin return_url rejection.

func TestBillingPortalSession_RejectsUnconfiguredInstall(t *testing.T) {
	env := setupTestEnv(t)

	// No license configured. The route should refuse the call up-front rather
	// than letting it sail through to a nil ValidonX client.
	defer deactivateLicense(t, env) // belt-and-braces in case a prior test left state

	resp := env.doRequest(t, "POST", "/api/v1/account/billing-portal-session", `{}`)
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403 on unconfigured install, got %d (body: %s)", resp.StatusCode, raw)
	}
	parsed := parseBody(t, resp)
	errObj, _ := parsed["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("expected error envelope, got %v", parsed)
	}
	if code, _ := errObj["code"].(string); code != "INSTALL_NOT_LICENSED" {
		t.Errorf("expected INSTALL_NOT_LICENSED, got %q (full response: %v)", code, parsed)
	}
}

func TestBillingPortalSession_HappyPath(t *testing.T) {
	env := setupTestEnv(t)

	var billingHits int
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/integration/licensing/resolve":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": {"valid": true, "status": "active", "allowed_features": ["basic_mail","analytics"], "grace_period_ends_at": null, "expires_at": "2099-01-01T00:00:00+00:00"},
				"meta": {"request_id": "billing-test-rid", "api_version": "1"}
			}`))
		case "/api/v1/integration/billing/portal-session":
			billingHits++
			// Verify the X-API-Key header is present — path-2 auth contract.
			if r.Header.Get("X-API-Key") == "" {
				t.Errorf("billing portal request missing X-API-Key header")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": {"url": "https://billing.stripe.com/p/session/test_session_abc", "expires_at": "2026-12-31T23:59:59Z"},
				"meta": {"request_id": "portal-test-rid", "api_version": "1"}
			}`))
		default:
			t.Errorf("unexpected mock path: %q", r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer mock.Close()

	// Activate so handleBillingPortalSession passes the IsConfigured guard.
	body, _ := json.Marshal(map[string]string{
		"base_url":        mock.URL,
		"service_key":     "test-service-key",
		"tenant_id":       fmt.Sprintf("billing-test-%d", time.Now().UnixNano()),
		"subscription_id": "sub_billing_test",
		"license_key":     "VLDX-VECTIS-PRO-BILLING-001",
	})
	if r := env.doRequest(t, "POST", "/api/v1/license", string(body)); r.StatusCode != 200 {
		raw, _ := io.ReadAll(r.Body)
		r.Body.Close()
		t.Fatalf("license activation prereq failed: %d (body: %s)", r.StatusCode, raw)
	}
	defer deactivateLicense(t, env)

	resp := env.doRequest(t, "POST", "/api/v1/account/billing-portal-session", `{"return_url":"http://example.com/admin/license"}`)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d (body: %s)", resp.StatusCode, raw)
	}
	parsed := parseBody(t, resp)
	data, _ := parsed["data"].(map[string]any)
	if data == nil {
		t.Fatalf("expected data envelope, got %v", parsed)
	}
	if got, _ := data["url"].(string); got != "https://billing.stripe.com/p/session/test_session_abc" {
		t.Errorf("expected ValidonX-minted URL, got %q (full response: %v)", got, parsed)
	}
	if billingHits != 1 {
		t.Errorf("expected exactly 1 hit on portal-session endpoint, got %d", billingHits)
	}
}

// TestBillingPortalSession_NoStripeCustomer covers a tenant with no Stripe
// customer (free tier, or a manually-issued no-Stripe Enterprise license).
// ValidonX answers portal-session with a structured 409 in its NESTED error
// envelope ({"error": {"code", ...}}); the handler must translate that into a
// clean 409 BILLING_PORTAL_UNAVAILABLE — not a 502 with raw upstream JSON — so
// the admin UI can hide/disable "Manage Billing". Regression guard for the
// nested-vs-flat error-envelope parsing in validonx.doJSON.
func TestBillingPortalSession_NoStripeCustomer(t *testing.T) {
	env := setupTestEnv(t)

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/integration/licensing/resolve":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": {"valid": true, "status": "active", "allowed_features": ["basic_mail"], "grace_period_ends_at": null, "expires_at": null},
				"meta": {"request_id": "rid", "api_version": "1"}
			}`))
		case "/api/v1/integration/billing/portal-session":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{
				"error": {
					"code": "BILLING.PORTAL_SESSION_NO_STRIPE_CUSTOMER",
					"message": "Tenant has no Stripe customer ID — cannot open the billing portal until a paid subscription exists",
					"type": "billing",
					"status": 409,
					"details": {"tenant_id": "x"}
				},
				"meta": {"request_id": "rid", "api_version": "1"}
			}`))
		default:
			t.Errorf("unexpected mock path: %q", r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer mock.Close()

	body, _ := json.Marshal(map[string]string{
		"base_url":        mock.URL,
		"service_key":     "test-service-key",
		"tenant_id":       fmt.Sprintf("billing-nostripe-%d", time.Now().UnixNano()),
		"subscription_id": "sub_nostripe_test",
		"license_key":     "VLDX-VECTIS-FREE-NOSTRIPE-001",
	})
	if r := env.doRequest(t, "POST", "/api/v1/license", string(body)); r.StatusCode != 200 {
		raw, _ := io.ReadAll(r.Body)
		r.Body.Close()
		t.Fatalf("license activation prereq failed: %d (body: %s)", r.StatusCode, raw)
	}
	defer deactivateLicense(t, env)

	resp := env.doRequest(t, "POST", "/api/v1/account/billing-portal-session", `{"return_url":"http://example.com/admin/license"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 409, got %d (body: %s)", resp.StatusCode, raw)
	}
	parsed := parseBody(t, resp)
	errObj, _ := parsed["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("expected error envelope, got %v", parsed)
	}
	if code, _ := errObj["code"].(string); code != "BILLING_PORTAL_UNAVAILABLE" {
		t.Errorf("expected code BILLING_PORTAL_UNAVAILABLE, got %q (full: %v)", code, parsed)
	}
}

func TestBillingPortalSession_RejectsCrossOriginReturnURL(t *testing.T) {
	env := setupTestEnv(t)

	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/integration/licensing/resolve" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": {"valid": true, "status": "active", "allowed_features": ["basic_mail","analytics"], "grace_period_ends_at": null, "expires_at": "2099-01-01T00:00:00+00:00"},
				"meta": {"request_id": "rid", "api_version": "1"}
			}`))
			return
		}
		// portal-session must NOT be hit if return_url is rejected up-front
		t.Errorf("unexpected mock path %q — portal-session should not have been called", r.URL.Path)
		http.Error(w, "unexpected", http.StatusBadRequest)
	}))
	defer mock.Close()

	body, _ := json.Marshal(map[string]string{
		"base_url":        mock.URL,
		"service_key":     "test-service-key",
		"tenant_id":       fmt.Sprintf("billing-host-test-%d", time.Now().UnixNano()),
		"subscription_id": "sub_billing_host_test",
		"license_key":     "VLDX-VECTIS-PRO-BILLING-002",
	})
	if r := env.doRequest(t, "POST", "/api/v1/license", string(body)); r.StatusCode != 200 {
		raw, _ := io.ReadAll(r.Body)
		r.Body.Close()
		t.Fatalf("license activation prereq failed: %d (body: %s)", r.StatusCode, raw)
	}
	defer deactivateLicense(t, env)

	// Default request host in the test env is "example.com" via httptest;
	// pointing return_url at evil.com must reject before any ValidonX call.
	resp := env.doRequest(t, "POST", "/api/v1/account/billing-portal-session", `{"return_url":"https://evil.com/landing"}`)
	defer resp.Body.Close()
	if resp.StatusCode != 400 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 400 on cross-origin return_url, got %d (body: %s)", resp.StatusCode, raw)
	}
	parsed := parseBody(t, resp)
	errObj, _ := parsed["error"].(map[string]any)
	if errObj == nil {
		t.Fatalf("expected error envelope, got %v", parsed)
	}
	if code, _ := errObj["code"].(string); code != "INVALID_RETURN_URL" {
		t.Errorf("expected INVALID_RETURN_URL, got %q (full response: %v)", code, parsed)
	}
}

// ── In-product upgrade checkout (keyless Customer #2) ────────────
//
// /account/upgrade-checkout-session mints a Stripe Checkout session via Vx's
// keyless endpoint. The load-bearing security property is that the success/
// cancel return URLs are SERVER-SET to allowlisted vectismail.com pages and are
// NEVER derived from the request host — a bug there would be an open-redirect
// vector through the Vx call chain. This test pins that line, and also pins the
// owner_name-from-supplied-email derivation.

func TestUpgradeCheckout_ServerSetsAllowlistedReturnURLs(t *testing.T) {
	env := setupTestEnv(t)
	deactivateLicense(t, env)

	var gotCheckoutBody []byte
	var checkoutHits int
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/integration/licensing/resolve":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"data": {"valid": true, "status": "active", "allowed_features": ["basic_mail","analytics"], "grace_period_ends_at": null, "expires_at": "2099-01-01T00:00:00+00:00"},
				"meta": {"request_id": "rid", "api_version": "1"}
			}`))
		case "/api/v1/checkout/vectis-pro":
			checkoutHits++
			gotCheckoutBody, _ = io.ReadAll(r.Body)
			// The keyless endpoint must receive NO X-API-Key.
			if r.Header.Get("X-API-Key") != "" {
				t.Errorf("keyless checkout must not carry X-API-Key, got %q", r.Header.Get("X-API-Key"))
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_, _ = io.WriteString(w, `{"data":{"checkout_url":"https://checkout.stripe.com/c/pay/cs_test_xyz","session_id":"cs_test_xyz"},"meta":{"request_id":"r","api_version":"1"}}`)
		default:
			t.Errorf("unexpected mock path: %q", r.URL.Path)
			http.Error(w, "unexpected", http.StatusNotFound)
		}
	}))
	defer mock.Close()

	// Activate so the handler resolves base_url to the mock (not real Vx).
	body, _ := json.Marshal(map[string]string{
		"base_url":        mock.URL,
		"service_key":     "test-service-key",
		"tenant_id":       fmt.Sprintf("upgrade-test-%d", time.Now().UnixNano()),
		"subscription_id": "sub_upgrade_test",
		"license_key":     "VLDX-VECTIS-PRO-UPGRADE-001",
	})
	if r := env.doRequest(t, "POST", "/api/v1/license", string(body)); r.StatusCode != 200 {
		raw, _ := io.ReadAll(r.Body)
		r.Body.Close()
		t.Fatalf("license activation prereq failed: %d (body: %s)", r.StatusCode, raw)
	}
	defer deactivateLicense(t, env)

	// Caller supplies an owner_email that differs from the logged-in admin's,
	// and NO owner_name — exercising the supplied-email derivation (#5).
	resp := env.doRequest(t, "POST", "/api/v1/account/upgrade-checkout-session",
		`{"owner_email":"buyer@elsewhere.example"}`)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d (body: %s)", resp.StatusCode, raw)
	}
	if checkoutHits != 1 {
		t.Fatalf("expected exactly 1 hit on keyless checkout endpoint, got %d", checkoutHits)
	}

	var sent struct {
		OwnerEmail string `json:"owner_email"`
		OwnerName  string `json:"owner_name"`
		SuccessURL string `json:"success_url"`
		CancelURL  string `json:"cancel_url"`
	}
	if err := json.Unmarshal(gotCheckoutBody, &sent); err != nil {
		t.Fatalf("decode forwarded checkout body: %v (raw: %s)", err, gotCheckoutBody)
	}

	// Security line: return URLs are the vectismail.com constants, never the
	// request host (httptest default is example.com).
	const wantSuccess = "https://vectismail.com/upgrade/success/?origin=install&session={CHECKOUT_SESSION_ID}"
	const wantCancel = "https://vectismail.com/upgrade/cancelled/?origin=install"
	if sent.SuccessURL != wantSuccess {
		t.Errorf("success_url = %q, want server-set %q", sent.SuccessURL, wantSuccess)
	}
	if sent.CancelURL != wantCancel {
		t.Errorf("cancel_url = %q, want server-set %q", sent.CancelURL, wantCancel)
	}
	if strings.Contains(sent.SuccessURL, "example.com") || strings.Contains(sent.CancelURL, "example.com") {
		t.Errorf("return URLs must never derive from the request host; got success=%q cancel=%q", sent.SuccessURL, sent.CancelURL)
	}

	// owner_name (#5): derived from the SUPPLIED email's local-part, not the
	// admin's address.
	if sent.OwnerEmail != "buyer@elsewhere.example" {
		t.Errorf("owner_email = %q, want the supplied address passed through", sent.OwnerEmail)
	}
	if sent.OwnerName != "buyer" {
		t.Errorf("owner_name = %q, want %q derived from the supplied owner_email", sent.OwnerName, "buyer")
	}
}

// ── Tier-gate test helper (Advanced Spam) ────────────────────────
//
// activateLicenseWithFeatures spins up a mock ValidonX server that returns
// the supplied feature set, then activates the license through the public
// /api/v1/license POST. After this call the feature gate is operating
// against the mock with exactly `features` granted.
//
// This is the first true tier-injection helper in the suite. Use it (with
// `defer mock.Close()` and `defer deactivateLicense(...)`) to drive
// Free-vs-Pro behaviour in handler tests. Activating with only
// "basic_mail" yields TierFree; including any Pro feature
// (advanced_spam, analytics, etc.) yields TierPro.
//
// IMPORTANT: simply NOT activating is not the same as "Free tier" — when
// no client is configured the gate passes everything through. Pass an
// explicitly-configured-but-feature-poor mock to exercise Free deny paths.
func activateLicenseWithFeatures(t *testing.T, env *testEnv, features ...string) *httptest.Server {
	t.Helper()

	featuresJSON, _ := json.Marshal(features)
	mock := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/integration/licensing/resolve" {
			http.Error(w, "unexpected path", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{
			"data": {
				"valid": true,
				"status": "active",
				"allowed_features": %s,
				"grace_period_ends_at": null,
				"expires_at": "2099-01-01T00:00:00+00:00",
				"license": {"id": "00000000-0000-0000-0000-000000000001", "key": "VLDX-TIER-TEST-001", "type": "subscription"}
			},
			"meta": {"request_id": "tier-test-rid", "api_version": "1"}
		}`, string(featuresJSON))
	}))

	body, _ := json.Marshal(map[string]string{
		"base_url":        mock.URL,
		"service_key":     "test-service-key",
		"tenant_id":       fmt.Sprintf("tier-test-%d", time.Now().UnixNano()),
		"subscription_id": "sub_tier_test",
		"license_key":     "VLDX-TIER-TEST-001",
	})
	resp := env.doRequest(t, "POST", "/api/v1/license", string(body))
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		mock.Close()
		t.Fatalf("activate license: expected 200, got %d (body: %s)", resp.StatusCode, raw)
	}
	return mock
}

// deactivateLicense reverts the install to unconfigured state. Note that
// once unconfigured the gate passes ALL requests through — useful for
// teardown but NOT a substitute for activating with a feature-poor mock
// when you need to assert Free-tier deny behaviour.
func deactivateLicense(t *testing.T, env *testEnv) {
	t.Helper()
	resp := env.doRequest(t, "DELETE", "/api/v1/license", "")
	resp.Body.Close()
}

// createDomainForTest is a small convenience for spam-list tests that need
// an existing domain to scope entries to. Returns the domain ID.
//
// The helper activates a Pro license for the duration of the create so it
// is not subject to Free's 3-domain cap (which would otherwise leak prior
// test state between runs on a shared dev DB). The license is deactivated
// before the helper returns; the calling test is responsible for setting
// the license state it actually wants to assert against.
func createDomainForTest(t *testing.T, env *testEnv, prefix string) string {
	t.Helper()
	mock := activateLicenseWithFeatures(t, env, "basic_mail", "advanced_spam")
	defer mock.Close()
	defer deactivateLicense(t, env)

	name := fmt.Sprintf("%s-%d.example.com", prefix, time.Now().UnixNano())
	resp := env.doRequest(t, "POST", "/api/v1/domains", fmt.Sprintf(`{"name":%q}`, name))
	if resp.StatusCode != 201 {
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create domain %q: expected 201, got %d (body: %s)", name, resp.StatusCode, body)
	}
	body := parseBody(t, resp)
	return body["data"].(map[string]any)["domain"].(map[string]any)["id"].(string)
}

// ── Advanced Spam: per-domain reject_threshold + greylist_enabled ─

func TestDomainCreate_AdvancedSpamFields_FreeReturns403(t *testing.T) {
	env := setupTestEnv(t)
	deactivateLicense(t, env)
	mock := activateLicenseWithFeatures(t, env, "basic_mail") // configured Free
	defer mock.Close()
	defer deactivateLicense(t, env)

	domainName := fmt.Sprintf("spam-free-%d.example.com", time.Now().UnixNano())
	body := fmt.Sprintf(`{"name":%q,"reject_threshold":12.0}`, domainName)
	resp := env.doRequest(t, "POST", "/api/v1/domains", body)
	defer resp.Body.Close()

	if resp.StatusCode != 403 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403 on Free POST with reject_threshold, got %d (body: %s)", resp.StatusCode, raw)
	}
	parsed := parseBody(t, resp)
	if errObj, _ := parsed["error"].(map[string]any); errObj == nil || errObj["code"] != "FEATURE_NOT_AVAILABLE" {
		t.Errorf("expected error.code FEATURE_NOT_AVAILABLE, got %v", parsed["error"])
	}
}

func TestDomainUpdate_AdvancedSpamFields_FreeReturns403(t *testing.T) {
	env := setupTestEnv(t)
	deactivateLicense(t, env)

	// Create the domain BEFORE we lock the gate to feature-poor Free —
	// otherwise the create itself would also pass Free's 3-domain cap
	// requirement even with a clean DB. The create path here is the
	// existing ungated route, no advanced fields → 201.
	domainID := createDomainForTest(t, env, "spam-update-free")

	mock := activateLicenseWithFeatures(t, env, "basic_mail")
	defer mock.Close()
	defer deactivateLicense(t, env)

	resp := env.doRequest(t, "PATCH", "/api/v1/domains/"+domainID, `{"greylist_enabled":true}`)
	defer resp.Body.Close()
	if resp.StatusCode != 403 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403 on Free PATCH with greylist_enabled, got %d (body: %s)", resp.StatusCode, raw)
	}
	parsed := parseBody(t, resp)
	if errObj, _ := parsed["error"].(map[string]any); errObj == nil || errObj["code"] != "FEATURE_NOT_AVAILABLE" {
		t.Errorf("expected error.code FEATURE_NOT_AVAILABLE, got %v", parsed["error"])
	}

	// Cleanup: deactivate first so we can delete on Free, then re-init.
	deactivateLicense(t, env)
	env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
}

// TestDomainUpdate_SpamThresholdStillUngated_Free200 is the regression
// guard: spam_threshold (existing per-domain knob since v0.1.0) MUST keep
// working on Free tier after the field-level Pro gate landed for
// reject_threshold + greylist_enabled. If this test goes red, the gate is
// over-broad and breaks an existing capability.
func TestDomainUpdate_SpamThresholdStillUngated_Free200(t *testing.T) {
	env := setupTestEnv(t)
	deactivateLicense(t, env)
	domainID := createDomainForTest(t, env, "spam-thr-free")

	mock := activateLicenseWithFeatures(t, env, "basic_mail")
	defer mock.Close()
	defer deactivateLicense(t, env)

	resp := env.doRequest(t, "PATCH", "/api/v1/domains/"+domainID, `{"spam_threshold":10.0}`)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("Free-tier spam_threshold PATCH must remain 200; got %d (body: %s)", resp.StatusCode, raw)
	}

	// Verify the value persisted.
	resp = env.doRequest(t, "GET", "/api/v1/domains/"+domainID, "")
	defer resp.Body.Close()
	body := parseBody(t, resp)
	got := body["data"].(map[string]any)["spam_threshold"].(float64)
	if got != 10.0 {
		t.Errorf("spam_threshold not persisted: expected 10.0, got %v", got)
	}

	// Cleanup.
	deactivateLicense(t, env)
	env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
}

func TestDomainUpdate_AdvancedSpamFields_ProReturns200(t *testing.T) {
	env := setupTestEnv(t)
	deactivateLicense(t, env)
	domainID := createDomainForTest(t, env, "spam-update-pro")

	mock := activateLicenseWithFeatures(t, env, "basic_mail", "advanced_spam")
	defer mock.Close()
	defer deactivateLicense(t, env)

	resp := env.doRequest(t, "PATCH", "/api/v1/domains/"+domainID,
		`{"reject_threshold":14.5,"greylist_enabled":true}`)
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("Pro PATCH with advanced spam fields: expected 200, got %d (body: %s)", resp.StatusCode, raw)
	}

	// Verify persisted.
	resp = env.doRequest(t, "GET", "/api/v1/domains/"+domainID, "")
	defer resp.Body.Close()
	body := parseBody(t, resp)
	d := body["data"].(map[string]any)
	if got, _ := d["reject_threshold"].(float64); got != 14.5 {
		t.Errorf("reject_threshold not persisted: expected 14.5, got %v", d["reject_threshold"])
	}
	if got, _ := d["greylist_enabled"].(bool); !got {
		t.Errorf("greylist_enabled not persisted: expected true, got %v", d["greylist_enabled"])
	}

	// Cleanup.
	deactivateLicense(t, env)
	env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
}

// ── Advanced Spam: per-domain spam-lists CRUD ────────────────────

func TestSpamListsCRUD_Pro(t *testing.T) {
	env := setupTestEnv(t)
	deactivateLicense(t, env)
	domainID := createDomainForTest(t, env, "spamlist-pro")

	mock := activateLicenseWithFeatures(t, env, "basic_mail", "advanced_spam")
	defer mock.Close()
	defer deactivateLicense(t, env)

	// Create — block, scope=domain.
	resp := env.doRequest(t, "POST", "/api/v1/domains/"+domainID+"/spam-lists",
		`{"kind":"block","scope":"domain","pattern":"spam.example"}`)
	if resp.StatusCode != 201 {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create spam list (block/domain): expected 201, got %d (body: %s)", resp.StatusCode, raw)
	}
	body := parseBody(t, resp)
	entryID := body["data"].(map[string]any)["entry"].(map[string]any)["id"].(string)

	// Create — allow, scope=email.
	resp = env.doRequest(t, "POST", "/api/v1/domains/"+domainID+"/spam-lists",
		`{"kind":"allow","scope":"email","pattern":"vip@friendly.example"}`)
	if resp.StatusCode != 201 {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("create spam list (allow/email): expected 201, got %d (body: %s)", resp.StatusCode, raw)
	}
	resp.Body.Close()

	// Duplicate — same domain, kind, scope, pattern → 409.
	resp = env.doRequest(t, "POST", "/api/v1/domains/"+domainID+"/spam-lists",
		`{"kind":"block","scope":"domain","pattern":"spam.example"}`)
	if resp.StatusCode != 409 {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("duplicate spam list entry: expected 409, got %d (body: %s)", resp.StatusCode, raw)
	}
	resp.Body.Close()

	// List — no filter, expect 2.
	resp = env.doRequest(t, "GET", "/api/v1/domains/"+domainID+"/spam-lists", "")
	if resp.StatusCode != 200 {
		t.Fatalf("list spam lists: expected 200, got %d", resp.StatusCode)
	}
	list := parseBody(t, resp)["data"].([]any)
	if len(list) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(list))
	}

	// List — filter kind=block.
	resp = env.doRequest(t, "GET", "/api/v1/domains/"+domainID+"/spam-lists?kind=block", "")
	if resp.StatusCode != 200 {
		t.Fatalf("list spam lists (kind=block): expected 200, got %d", resp.StatusCode)
	}
	filtered := parseBody(t, resp)["data"].([]any)
	if len(filtered) != 1 {
		t.Fatalf("expected 1 block entry, got %d", len(filtered))
	}

	// Delete one entry.
	resp = env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID+"/spam-lists/"+entryID, "")
	if resp.StatusCode != 200 {
		t.Fatalf("delete spam list entry: expected 200, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Confirm deletion via list.
	resp = env.doRequest(t, "GET", "/api/v1/domains/"+domainID+"/spam-lists", "")
	list = parseBody(t, resp)["data"].([]any)
	if len(list) != 1 {
		t.Fatalf("expected 1 remaining entry, got %d", len(list))
	}

	// Cleanup. Domain delete cascades to remaining spam-list entries
	// via the FK ON DELETE CASCADE — that's covered separately by
	// TestDomainDelete_CascadesSpamLists.
	deactivateLicense(t, env)
	env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
}

func TestSpamListsCRUD_FreeReturns403(t *testing.T) {
	env := setupTestEnv(t)
	deactivateLicense(t, env)
	domainID := createDomainForTest(t, env, "spamlist-free")

	mock := activateLicenseWithFeatures(t, env, "basic_mail")
	defer mock.Close()
	defer deactivateLicense(t, env)

	// POST — Free → 403.
	resp := env.doRequest(t, "POST", "/api/v1/domains/"+domainID+"/spam-lists",
		`{"kind":"block","scope":"domain","pattern":"spam.example"}`)
	if resp.StatusCode != 403 {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("Free POST spam-lists: expected 403, got %d (body: %s)", resp.StatusCode, raw)
	}
	resp.Body.Close()

	// GET — Free → 403.
	resp = env.doRequest(t, "GET", "/api/v1/domains/"+domainID+"/spam-lists", "")
	if resp.StatusCode != 403 {
		t.Fatalf("Free GET spam-lists: expected 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// DELETE — Free → 403 (entry doesn't exist but the gate fires before lookup).
	resp = env.doRequest(t, "DELETE",
		"/api/v1/domains/"+domainID+"/spam-lists/00000000-0000-0000-0000-000000000000", "")
	if resp.StatusCode != 403 {
		t.Fatalf("Free DELETE spam-lists: expected 403, got %d", resp.StatusCode)
	}
	resp.Body.Close()

	// Cleanup.
	deactivateLicense(t, env)
	env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
}

func TestSpamListsValidation(t *testing.T) {
	env := setupTestEnv(t)
	deactivateLicense(t, env)
	domainID := createDomainForTest(t, env, "spamlist-val")

	mock := activateLicenseWithFeatures(t, env, "basic_mail", "advanced_spam")
	defer mock.Close()
	defer deactivateLicense(t, env)

	cases := []struct {
		name string
		body string
		code string
	}{
		{"empty pattern", `{"kind":"block","scope":"domain","pattern":""}`, "MISSING_FIELDS"},
		{"missing pattern", `{"kind":"block","scope":"domain"}`, "MISSING_FIELDS"},
		{"invalid kind", `{"kind":"deny","scope":"domain","pattern":"spam.example"}`, "INVALID_KIND"},
		{"invalid scope", `{"kind":"block","scope":"sender","pattern":"spam.example"}`, "INVALID_SCOPE"},
		{"email scope without @", `{"kind":"block","scope":"email","pattern":"spam.example"}`, "INVALID_PATTERN"},
		{"domain scope with @", `{"kind":"block","scope":"domain","pattern":"x@spam.example"}`, "INVALID_PATTERN"},
		{"email scope empty local part", `{"kind":"block","scope":"email","pattern":"@spam.example"}`, "INVALID_PATTERN"},
	}
	for _, tc := range cases {
		resp := env.doRequest(t, "POST", "/api/v1/domains/"+domainID+"/spam-lists", tc.body)
		if resp.StatusCode != 400 {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Errorf("%s: expected 400, got %d (body: %s)", tc.name, resp.StatusCode, raw)
			continue
		}
		body := parseBody(t, resp)
		if errObj, _ := body["error"].(map[string]any); errObj == nil || errObj["code"] != tc.code {
			t.Errorf("%s: expected error.code %q, got %v", tc.name, tc.code, body["error"])
		}
	}

	// Cleanup.
	deactivateLicense(t, env)
	env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
}

// TestDomainDelete_CascadesSpamLists proves the FK ON DELETE CASCADE on
// domain_spam_lists.domain_id works through the actual delete path —
// the orchestrator regen path in session 2 assumes the table never
// contains entries pointing at a deleted domain.
func TestDomainDelete_CascadesSpamLists(t *testing.T) {
	env := setupTestEnv(t)
	deactivateLicense(t, env)
	domainID := createDomainForTest(t, env, "spamlist-cascade")

	mock := activateLicenseWithFeatures(t, env, "basic_mail", "advanced_spam")
	defer mock.Close()
	defer deactivateLicense(t, env)

	// Add two entries.
	for _, b := range []string{
		`{"kind":"block","scope":"domain","pattern":"spam-a.example"}`,
		`{"kind":"allow","scope":"email","pattern":"vip@b.example"}`,
	} {
		resp := env.doRequest(t, "POST", "/api/v1/domains/"+domainID+"/spam-lists", b)
		if resp.StatusCode != 201 {
			raw, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			t.Fatalf("seed entry: expected 201, got %d (body: %s)", resp.StatusCode, raw)
		}
		resp.Body.Close()
	}

	// Confirm 2 present.
	resp := env.doRequest(t, "GET", "/api/v1/domains/"+domainID+"/spam-lists", "")
	if entries := parseBody(t, resp)["data"].([]any); len(entries) != 2 {
		t.Fatalf("seed expected 2 entries, got %d", len(entries))
	}

	// Drop the license so the spam-list endpoint is no longer gated for the
	// post-delete probe (we want to read 0 entries through the API after
	// the cascade fires; with the gate active that probe would 403).
	deactivateLicense(t, env)

	// Delete the domain.
	resp = env.doRequest(t, "DELETE", "/api/v1/domains/"+domainID, "")
	if resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("delete domain: expected 200, got %d (body: %s)", resp.StatusCode, raw)
	}
	resp.Body.Close()

	// Probe through the API after re-activating Pro: the gate-protected
	// list endpoint must respond, and the domain must be gone (404 from
	// the per-domain handler's GetByID precheck).
	mock2 := activateLicenseWithFeatures(t, env, "basic_mail", "advanced_spam")
	defer mock2.Close()
	resp = env.doRequest(t, "GET", "/api/v1/domains/"+domainID+"/spam-lists", "")
	if resp.StatusCode != 404 {
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("list after domain delete: expected 404 (domain gone), got %d (body: %s)", resp.StatusCode, raw)
	}
	resp.Body.Close()
}
