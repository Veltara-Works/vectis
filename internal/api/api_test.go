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
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/api"
	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/repository"
)

type testEnv struct {
	server  *api.Server
	handler http.Handler
	cookie  string
	adminID string
}

func setupTestEnv(t *testing.T) *testEnv {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))

	pool, err := database.NewPool(ctx, database.Config{
		Host: "127.0.0.1", Port: 5432, Name: "vectis",
		User: "postgres", Password: "vectis_dev_super",
	}, logger)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}

	vk, err := database.NewValkeyClient(database.ValkeyConfig{
		Host: "127.0.0.1", Port: 6379, Password: "vectis_dev_valkey",
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

	// Seed an admin for tests.
	adminRepo := repository.NewAdminRepo(pool)
	hash, _ := auth.HashPassword("test-password")
	admin, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        fmt.Sprintf("test-%d@example.com", time.Now().UnixNano()),
		PasswordHash: hash,
	})
	if err != nil {
		t.Fatalf("create admin: %v", err)
	}

	env := &testEnv{
		server:  srv,
		handler: srv.Handler(),
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
