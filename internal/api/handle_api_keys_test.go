//go:build integration

package api_test

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

// decodeJSONBytes unmarshals a response body already read into memory (used
// when the same bytes are also scanned textually, e.g. for leak checks).
func decodeJSONBytes(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	return m
}

// createAPIKey creates an API key as the currently-authenticated identity and
// returns the new key's id and the one-time raw key. Fails if create != 201.
func createAPIKey(t *testing.T, env *testEnv, cookie, name string) (id, rawKey string) {
	t.Helper()
	resp := env.doAs(t, cookie, "POST", "/api/v1/api-keys", fmt.Sprintf(`{"name":%q}`, name))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create api key %q: expected 201, got %d (%v)", name, resp.StatusCode, parseBody(t, resp))
	}
	data := parseBody(t, resp)["data"].(map[string]any)
	apiKey := data["api_key"].(map[string]any)
	return apiKey["id"].(string), data["key"].(string)
}

// ── API keys: create + revoke happy path ─────────────────────────────

func TestAPIKeyCRUD(t *testing.T) {
	env := setupTestEnv(t)

	// Create. The raw key is returned exactly once; the hash must never appear.
	resp := env.doRequest(t, "POST", "/api/v1/api-keys", `{"name":"ci-test-key"}`)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create: expected 201, got %d", resp.StatusCode)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(raw), "key_hash") {
		t.Error("key_hash leaked in create response")
	}
	body := decodeJSONBytes(t, raw)
	data := body["data"].(map[string]any)
	if data["key"] == nil || data["key"] == "" {
		t.Fatal("expected one-time raw key in create response")
	}
	apiKey := data["api_key"].(map[string]any)
	keyID := apiKey["id"].(string)
	if apiKey["key_prefix"] == nil || apiKey["key_prefix"] == "" {
		t.Error("expected key_prefix in api_key view")
	}

	// List (as the seeded super_admin) includes the new key.
	resp = env.doRequest(t, "GET", "/api/v1/api-keys", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list: expected 200, got %d", resp.StatusCode)
	}
	keys := parseBody(t, resp)["data"].([]any)
	if !containsKey(keys, keyID) {
		t.Fatalf("created key %s not present in list", keyID)
	}

	// Revoke. The row is marked inactive (not deleted), so revoke is idempotent.
	resp = env.doRequest(t, "DELETE", "/api/v1/api-keys/"+keyID, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke: expected 200, got %d", resp.StatusCode)
	}

	// The key now reports active=false in the listing.
	resp = env.doRequest(t, "GET", "/api/v1/api-keys", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list after revoke: expected 200, got %d", resp.StatusCode)
	}
	for _, k := range parseBody(t, resp)["data"].([]any) {
		if m := k.(map[string]any); m["id"] == keyID {
			if m["active"] != false {
				t.Errorf("revoked key active = %v, want false", m["active"])
			}
		}
	}

	// Revoking again still returns 200 — the row persists, just inactive.
	resp = env.doRequest(t, "DELETE", "/api/v1/api-keys/"+keyID, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("idempotent re-revoke: expected 200, got %d", resp.StatusCode)
	}
}

// TestAPIKeyCreate_MissingName verifies the name is required.
func TestAPIKeyCreate_MissingName(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "POST", "/api/v1/api-keys", `{}`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", resp.StatusCode)
	}
	if code := parseBody(t, resp)["error"].(map[string]any)["code"]; code != "MISSING_FIELDS" {
		t.Errorf("error code = %v, want MISSING_FIELDS", code)
	}
}

// TestAPIKeyRevoke_NotFound verifies a well-formed but unknown id is 404.
func TestAPIKeyRevoke_NotFound(t *testing.T) {
	env := setupTestEnv(t)
	resp := env.doRequest(t, "DELETE", "/api/v1/api-keys/00000000-0000-0000-0000-000000000000", "")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", resp.StatusCode)
	}
}

// ── API keys: ownership enforcement ──────────────────────────────────

// TestAPIKeyRevoke_OwnershipEnforced verifies a non-super_admin cannot revoke
// another admin's key, but can revoke their own. CanManageAdmins is
// super_admin-only, so a plain admin is bound by the ownership check.
func TestAPIKeyRevoke_OwnershipEnforced(t *testing.T) {
	env := setupTestEnv(t)

	// Key owned by the seeded super_admin.
	superKeyID, _ := createAPIKey(t, env, env.cookie, "super-owned")

	// A plain admin acting for themselves.
	_, email := createAdmin(t, env, "admin")
	cookie := loginCookie(t, env, email, subAdminPassword)
	ownKeyID, _ := createAPIKey(t, env, cookie, "admin-owned")

	// The plain admin cannot revoke the super_admin's key.
	resp := env.doAs(t, cookie, "DELETE", "/api/v1/api-keys/"+superKeyID, "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("revoke other's key: expected 403, got %d", resp.StatusCode)
	}

	// But can revoke their own.
	resp = env.doAs(t, cookie, "DELETE", "/api/v1/api-keys/"+ownKeyID, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke own key: expected 200, got %d", resp.StatusCode)
	}
}

// TestAPIKeyList_NonManagerSeesOwnOnly verifies a plain admin's list is scoped
// to their own keys (the super_admin sees all via ListAll).
func TestAPIKeyList_NonManagerSeesOwnOnly(t *testing.T) {
	env := setupTestEnv(t)

	superKeyID, _ := createAPIKey(t, env, env.cookie, fmt.Sprintf("super-%d", time.Now().UnixNano()))

	_, email := createAdmin(t, env, "admin")
	cookie := loginCookie(t, env, email, subAdminPassword)
	ownKeyID, _ := createAPIKey(t, env, cookie, fmt.Sprintf("own-%d", time.Now().UnixNano()))

	resp := env.doAs(t, cookie, "GET", "/api/v1/api-keys", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list as admin: expected 200, got %d", resp.StatusCode)
	}
	keys := parseBody(t, resp)["data"].([]any)
	if !containsKey(keys, ownKeyID) {
		t.Error("admin's own key missing from their list")
	}
	if containsKey(keys, superKeyID) {
		t.Error("admin's list leaked the super_admin's key")
	}
}

// containsKey reports whether a list of api-key views contains the given id.
func containsKey(keys []any, id string) bool {
	for _, k := range keys {
		if m, ok := k.(map[string]any); ok && m["id"] == id {
			return true
		}
	}
	return false
}
