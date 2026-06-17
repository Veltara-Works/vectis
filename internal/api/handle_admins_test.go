//go:build integration

package api_test

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// ── Shared helpers for role/ownership tests ──────────────────────────
//
// The base setupTestEnv seeds a single super_admin and logs in as it. The
// tests below also need to act as lower-privilege identities (a plain `admin`)
// to exercise the role gates, so these helpers create a secondary admin via the
// super_admin API surface and obtain a session cookie for it.

const subAdminPassword = "sub-admin-password-123"

// createAdmin creates an admin with the given role via POST /admins (acting as
// the seeded super_admin) and returns its id and email. Fails the test if the
// create does not return 201.
func createAdmin(t *testing.T, env *testEnv, role string) (id, email string) {
	t.Helper()
	email = fmt.Sprintf("sub-%s-%d@example.com", role, time.Now().UnixNano())
	body := fmt.Sprintf(`{"email":%q,"password":%q,"role":%q}`, email, subAdminPassword, role)
	resp := env.doRequest(t, "POST", "/api/v1/admins", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create %s admin: expected 201, got %d (%v)", role, resp.StatusCode, parseBody(t, resp))
	}
	data := parseBody(t, resp)["data"].(map[string]any)
	return data["id"].(string), email
}

// loginCookie logs in and returns the session cookie value.
func loginCookie(t *testing.T, env *testEnv, email, password string) string {
	t.Helper()
	resp := env.doRequest(t, "POST", "/api/v1/auth/login",
		fmt.Sprintf(`{"email":%q,"password":%q}`, email, password))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login %s: expected 200, got %d", email, resp.StatusCode)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == "vectis_session" {
			return c.Value
		}
	}
	t.Fatalf("login %s: no session cookie returned", email)
	return ""
}

// doAs runs a request with a specific session cookie, restoring the env's
// original cookie afterwards. Safe because the integration suite runs serially
// (-p 1) and a single test never issues concurrent requests.
func (e *testEnv) doAs(t *testing.T, cookie, method, path, body string) *http.Response {
	t.Helper()
	saved := e.cookie
	e.cookie = cookie
	defer func() { e.cookie = saved }()
	return e.doRequest(t, method, path, body)
}

// ── Admins: role gates ───────────────────────────────────────────────

// TestAdminWrites_RequireSuperAdmin verifies that a plain `admin` cannot
// create, update, or delete admins — those routes are gated by
// requireSuperAdmin(). GET /admins remains accessible to any authenticated
// admin.
func TestAdminWrites_RequireSuperAdmin(t *testing.T) {
	env := setupTestEnv(t)

	// Create a plain admin and act as them.
	targetID, email := createAdmin(t, env, "admin")
	cookie := loginCookie(t, env, email, subAdminPassword)

	// GET /admins is allowed for a plain admin.
	if resp := env.doAs(t, cookie, "GET", "/api/v1/admins", ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admins as admin: expected 200, got %d", resp.StatusCode)
	}

	// POST /admins is forbidden.
	create := `{"email":"nope-` + fmt.Sprint(time.Now().UnixNano()) + `@example.com","password":"another-password-1","role":"admin"}`
	if resp := env.doAs(t, cookie, "POST", "/api/v1/admins", create); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("POST /admins as admin: expected 403, got %d", resp.StatusCode)
	}

	// PATCH /admins/{id} is forbidden.
	if resp := env.doAs(t, cookie, "PATCH", "/api/v1/admins/"+targetID, `{"email":"x@example.com"}`); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("PATCH /admins as admin: expected 403, got %d", resp.StatusCode)
	}

	// DELETE /admins/{id} is forbidden (gate runs before the confirm-header check).
	if resp := env.doAs(t, cookie, "DELETE", "/api/v1/admins/"+targetID, ""); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("DELETE /admins as admin: expected 403, got %d", resp.StatusCode)
	}
}

// ── Admins: CRUD happy path ──────────────────────────────────────────

func TestAdminCRUD(t *testing.T) {
	env := setupTestEnv(t)

	// Create.
	id, email := createAdmin(t, env, "admin")

	// The create response must never leak the password hash.
	resp := env.doRequest(t, "GET", "/api/v1/admins", "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("list admins: expected 200, got %d", resp.StatusCode)
	}
	listBody := parseBody(t, resp)
	admins := listBody["data"].([]any)
	found := false
	for _, a := range admins {
		m := a.(map[string]any)
		if m["id"] == id {
			found = true
			if m["email"] != email {
				t.Errorf("listed admin email = %v, want %s", m["email"], email)
			}
			if m["role"] != "admin" {
				t.Errorf("listed admin role = %v, want admin", m["role"])
			}
			if _, leaked := m["password_hash"]; leaked {
				t.Error("password_hash leaked in admin view")
			}
		}
	}
	if !found {
		t.Fatalf("created admin %s not present in list", id)
	}

	// Update the email via PATCH.
	newEmail := fmt.Sprintf("renamed-%d@example.com", time.Now().UnixNano())
	resp = env.doRequest(t, "PATCH", "/api/v1/admins/"+id, fmt.Sprintf(`{"email":%q}`, newEmail))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("patch admin: expected 200, got %d (%v)", resp.StatusCode, parseBody(t, resp))
	}
	if got := parseBody(t, resp)["data"].(map[string]any)["email"]; got != newEmail {
		t.Errorf("patched email = %v, want %s", got, newEmail)
	}

	// Delete (requires the confirmation header).
	resp = env.doRequestWithHeader(t, "DELETE", "/api/v1/admins/"+id, "", "X-Confirm-Delete", "true")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("delete admin: expected 200, got %d (%v)", resp.StatusCode, parseBody(t, resp))
	}

	// Gone — second delete is 404.
	resp = env.doRequestWithHeader(t, "DELETE", "/api/v1/admins/"+id, "", "X-Confirm-Delete", "true")
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("re-delete admin: expected 404, got %d", resp.StatusCode)
	}
}

// ── Admins: create validation ────────────────────────────────────────

func TestAdminCreate_Validation(t *testing.T) {
	env := setupTestEnv(t)

	cases := []struct {
		name string
		body string
		want int
		code string
	}{
		{"missing fields", `{"email":"a@example.com"}`, http.StatusBadRequest, "MISSING_FIELDS"},
		{"invalid email", `{"email":"not-an-email","password":"long-enough-1"}`, http.StatusBadRequest, "INVALID_EMAIL"},
		{"weak password", fmt.Sprintf(`{"email":"weak-%d@example.com","password":"short"}`, time.Now().UnixNano()), http.StatusBadRequest, "WEAK_PASSWORD"},
		{"invalid role", fmt.Sprintf(`{"email":"role-%d@example.com","password":"long-enough-1","role":"wizard"}`, time.Now().UnixNano()), http.StatusBadRequest, "INVALID_ROLE"},
		{"domain_admin without domains", fmt.Sprintf(`{"email":"da-%d@example.com","password":"long-enough-1","role":"domain_admin"}`, time.Now().UnixNano()), http.StatusBadRequest, "MISSING_DOMAINS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := env.doRequest(t, "POST", "/api/v1/admins", tc.body)
			if resp.StatusCode != tc.want {
				t.Fatalf("expected %d, got %d", tc.want, resp.StatusCode)
			}
			body := parseBody(t, resp)
			errObj, ok := body["error"].(map[string]any)
			if !ok {
				t.Fatalf("expected error object, got %v", body)
			}
			if errObj["code"] != tc.code {
				t.Errorf("error code = %v, want %s", errObj["code"], tc.code)
			}
		})
	}
}

// TestAdminCreate_DuplicateConflict verifies the uniqueness check returns 409.
func TestAdminCreate_DuplicateConflict(t *testing.T) {
	env := setupTestEnv(t)
	_, email := createAdmin(t, env, "admin")

	dup := fmt.Sprintf(`{"email":%q,"password":%q,"role":"admin"}`, email, subAdminPassword)
	resp := env.doRequest(t, "POST", "/api/v1/admins", dup)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("duplicate create: expected 409, got %d", resp.StatusCode)
	}
	if code := parseBody(t, resp)["error"].(map[string]any)["code"]; code != "ADMIN_EXISTS" {
		t.Errorf("error code = %v, want ADMIN_EXISTS", code)
	}
}

// ── Admins: delete guards ────────────────────────────────────────────

func TestAdminDelete_Guards(t *testing.T) {
	env := setupTestEnv(t)
	id, _ := createAdmin(t, env, "admin")

	// Missing confirmation header.
	resp := env.doRequest(t, "DELETE", "/api/v1/admins/"+id, "")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("delete without confirm header: expected 400, got %d", resp.StatusCode)
	}
	if code := parseBody(t, resp)["error"].(map[string]any)["code"]; code != "CONFIRMATION_REQUIRED" {
		t.Errorf("error code = %v, want CONFIRMATION_REQUIRED", code)
	}

	// Cannot delete yourself (acting super_admin's own id).
	resp = env.doRequestWithHeader(t, "DELETE", "/api/v1/admins/"+env.adminID, "", "X-Confirm-Delete", "true")
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("self-delete: expected 400, got %d", resp.StatusCode)
	}
	if code := parseBody(t, resp)["error"].(map[string]any)["code"]; code != "CANNOT_DELETE_SELF" {
		t.Errorf("error code = %v, want CANNOT_DELETE_SELF", code)
	}
}
