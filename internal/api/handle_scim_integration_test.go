//go:build integration

package api_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/Veltara-Works/vectis/internal/scim"
)

// SCIM 2.0 provisioning — DB-backed end-to-end coverage (Phase-1). Exercises
// the real router/middleware/gate/handlers against Postgres, covering:
//   - Enterprise gating: token-mgmt + /scim/v2 are 403 (SCIM-shaped) on a
//     configured-but-unentitled install ("don't expose SCIM below Enterprise").
//   - Auth matrix on /scim/v2: missing/malformed/unknown/revoked/expired → 401;
//     a valid scim_ token → 200 ("don't lock out a correctly-configured IdP").
//   - Realm isolation: a scim_ token is rejected on /api/v1.
//   - Token lifecycle: create → list → rotate (prior token revoked) → delete.
//   - User lifecycle: create → get → filter → duplicate-409 → patch active:false
//     → delete (deactivate, never erase).
//
// Gate state is driven by activateLicenseWithFeatures (mock ValidonX resolve +
// cache), the established integration seam. To assert a deny we activate a
// feature-poor license (configured, lacking "scim") rather than deactivating —
// see deactivateLicense's note.

const (
	scimUserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimPatchOp    = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

// insertSCIMToken writes a SCIM token directly via the repo, returning the raw
// bearer token and its id. Used for cases the public API can't mint: a valid
// token on a non-Enterprise install (gate would 403 the mint), and expired
// tokens (the API only mints future-dated ones).
func insertSCIMToken(t *testing.T, env *testEnv, active bool, expiresAt *time.Time) (raw, id string) {
	t.Helper()
	rawToken, hash, prefix, err := auth.GenerateSCIMToken()
	if err != nil {
		t.Fatalf("generate scim token: %v", err)
	}
	repo := repository.NewSCIMTokenRepo(env.pool)
	tok, err := repo.Create(context.Background(), repository.SCIMTokenCreate{
		TokenHash:   hash,
		TokenPrefix: prefix,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		t.Fatalf("insert scim token: %v", err)
	}
	if !active {
		if _, err := repo.Revoke(context.Background(), tok.ID); err != nil {
			t.Fatalf("revoke scim token: %v", err)
		}
	}
	return rawToken, tok.ID
}

// scimReq issues a /scim/v2 request bearing the given raw token.
func scimReq(t *testing.T, env *testEnv, method, path, token, body string) *http.Response {
	t.Helper()
	return env.doRequestWithHeader(t, method, path, body, "Authorization", "Bearer "+token)
}

func mustClose(resp *http.Response) { resp.Body.Close() }

// ── Enterprise gating ────────────────────────────────────────────────

func TestSCIM_TokenManagement_RequiresEnterprise(t *testing.T) {
	env := setupTestEnv(t)
	mock := activateLicenseWithFeatures(t, env, "basic_mail") // configured, no scim
	defer mock.Close()
	defer deactivateLicense(t, env)

	for _, tc := range []struct{ method, path, body string }{
		{"GET", "/api/v1/scim-tokens", ""},
		{"POST", "/api/v1/scim-tokens", "{}"},
	} {
		resp := env.doRequest(t, tc.method, tc.path, tc.body)
		if resp.StatusCode != http.StatusForbidden {
			raw, _ := io.ReadAll(resp.Body)
			t.Errorf("%s %s on non-Enterprise: expected 403, got %d (%s)", tc.method, tc.path, resp.StatusCode, raw)
		}
		mustClose(resp)
	}
}

func TestSCIM_Endpoints_RequireEnterprise(t *testing.T) {
	env := setupTestEnv(t)
	mock := activateLicenseWithFeatures(t, env, "basic_mail") // configured, no scim
	defer mock.Close()
	defer deactivateLicense(t, env)

	// A valid token still hits the gate after auth — non-Enterprise must 403.
	raw, _ := insertSCIMToken(t, env, true, nil)
	resp := scimReq(t, env, "GET", "/scim/v2/Users?filter=userName%20eq%20%22a@b.com%22", raw, "")
	defer mustClose(resp)
	if resp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 403 on non-Enterprise SCIM call, got %d (%s)", resp.StatusCode, body)
	}
	if ct := resp.Header.Get("Content-Type"); ct != scim.ContentType {
		t.Errorf("expected %s content-type, got %q", scim.ContentType, ct)
	}
	got := parseBody(t, resp)
	if schemas, ok := got["schemas"].([]any); !ok || len(schemas) == 0 {
		t.Errorf("expected SCIM error schemas, got %v", got["schemas"])
	}
}

// ── Auth matrix (gate open, isolate authentication) ───────────────────

func TestSCIM_AuthMatrix(t *testing.T) {
	env := setupTestEnv(t)
	mock := activateLicenseWithFeatures(t, env, "scim", "saml_sso")
	defer mock.Close()
	defer deactivateLicense(t, env)

	past := time.Now().Add(-1 * time.Hour)
	revokedRaw, _ := insertSCIMToken(t, env, false, nil)
	expiredRaw, _ := insertSCIMToken(t, env, true, &past)

	// Mint a valid token via the public API (gate is open).
	mintResp := env.doRequest(t, "POST", "/api/v1/scim-tokens", "{}")
	if mintResp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(mintResp.Body)
		t.Fatalf("mint scim token: expected 201, got %d (%s)", mintResp.StatusCode, raw)
	}
	validRaw := parseBody(t, mintResp)["data"].(map[string]any)["token"].(string)
	mustClose(mintResp)

	cases := []struct {
		name       string
		authHeader string
		wantStatus int
	}{
		{"missing token", "", http.StatusUnauthorized},
		{"wrong prefix", "Bearer vectis_deadbeef", http.StatusUnauthorized},
		{"unknown scim token", "Bearer scim_" + "00000000000000000000000000000000", http.StatusUnauthorized},
		{"revoked token", "Bearer " + revokedRaw, http.StatusUnauthorized},
		{"expired token", "Bearer " + expiredRaw, http.StatusUnauthorized},
		{"valid token", "Bearer " + validRaw, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var resp *http.Response
			if tc.authHeader == "" {
				resp = env.doRequest(t, "GET", "/scim/v2/Users", "")
			} else {
				resp = env.doRequestWithHeader(t, "GET", "/scim/v2/Users", "", "Authorization", tc.authHeader)
			}
			defer mustClose(resp)
			if resp.StatusCode != tc.wantStatus {
				body, _ := io.ReadAll(resp.Body)
				t.Fatalf("%s: expected %d, got %d (%s)", tc.name, tc.wantStatus, resp.StatusCode, body)
			}
			// Every response — success or failure — must be SCIM-typed.
			if ct := resp.Header.Get("Content-Type"); ct != scim.ContentType {
				t.Errorf("%s: expected %s content-type, got %q", tc.name, scim.ContentType, ct)
			}
		})
	}
}

func TestSCIM_TokenRejectedOnAdminAPI(t *testing.T) {
	env := setupTestEnv(t)
	raw, _ := insertSCIMToken(t, env, true, nil)
	// A SCIM token must not authenticate against /api/v1 (admin realm). Clear
	// the seeded super_admin session cookie so only the Bearer is presented —
	// otherwise the cookie would authenticate the request on its own.
	saved := env.cookie
	env.cookie = ""
	defer func() { env.cookie = saved }()
	resp := env.doRequestWithHeader(t, "GET", "/api/v1/domains", "", "Authorization", "Bearer "+raw)
	defer mustClose(resp)
	if resp.StatusCode != http.StatusUnauthorized {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("scim token on /api/v1/domains: expected 401, got %d (%s)", resp.StatusCode, body)
	}
}

// ── Token lifecycle ──────────────────────────────────────────────────

func TestSCIM_TokenLifecycle(t *testing.T) {
	env := setupTestEnv(t)
	mock := activateLicenseWithFeatures(t, env, "scim")
	defer mock.Close()
	defer deactivateLicense(t, env)

	mint := func() (raw, prefix string) {
		resp := env.doRequest(t, "POST", "/api/v1/scim-tokens", "{}")
		if resp.StatusCode != http.StatusCreated {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("mint: expected 201, got %d (%s)", resp.StatusCode, b)
		}
		data := parseBody(t, resp)["data"].(map[string]any)
		mustClose(resp)
		if data["endpoint_url"] == nil || data["endpoint_url"].(string) == "" {
			t.Error("mint response missing endpoint_url")
		}
		return data["token"].(string), data["scim_token"].(map[string]any)["token_prefix"].(string)
	}

	raw1, _ := mint()

	// First token authenticates.
	if resp := scimReq(t, env, "GET", "/scim/v2/Users", raw1, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("token 1 should authenticate: got %d", resp.StatusCode)
	} else {
		mustClose(resp)
	}

	// Rotate: a second mint revokes the first (single active token per install).
	raw2, _ := mint()
	if resp := scimReq(t, env, "GET", "/scim/v2/Users", raw1, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token 1 should be revoked after rotation: got %d", resp.StatusCode)
		mustClose(resp)
	} else {
		mustClose(resp)
	}
	if resp := scimReq(t, env, "GET", "/scim/v2/Users", raw2, ""); resp.StatusCode != http.StatusOK {
		t.Errorf("token 2 should authenticate: got %d", resp.StatusCode)
		mustClose(resp)
	} else {
		mustClose(resp)
	}

	// List shows both, exactly one active.
	listResp := env.doRequest(t, "GET", "/api/v1/scim-tokens", "")
	tokens := parseBody(t, listResp)["data"].([]any)
	mustClose(listResp)
	active := 0
	var activeID string
	for _, x := range tokens {
		tk := x.(map[string]any)
		if tk["active"].(bool) {
			active++
			activeID = tk["id"].(string)
		}
	}
	if active != 1 {
		t.Errorf("expected exactly 1 active token after rotation, got %d", active)
	}

	// Delete the active token → it stops authenticating.
	delResp := env.doRequest(t, "DELETE", "/api/v1/scim-tokens/"+activeID, "")
	if delResp.StatusCode != http.StatusOK {
		t.Errorf("delete token: expected 200, got %d", delResp.StatusCode)
	}
	mustClose(delResp)
	if resp := scimReq(t, env, "GET", "/scim/v2/Users", raw2, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("token 2 should be revoked after delete: got %d", resp.StatusCode)
		mustClose(resp)
	} else {
		mustClose(resp)
	}
}

// ── User lifecycle ───────────────────────────────────────────────────

func TestSCIM_UserLifecycle(t *testing.T) {
	env := setupTestEnv(t)
	mock := activateLicenseWithFeatures(t, env, "scim", "basic_mail")
	defer mock.Close()
	defer deactivateLicense(t, env)

	// Provision a domain (userName's domain must pre-exist).
	domainName := fmt.Sprintf("scim-e2e-%d.example.com", time.Now().UnixNano())
	dResp := env.doRequest(t, "POST", "/api/v1/domains", fmt.Sprintf(`{"name":%q}`, domainName))
	if dResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(dResp.Body)
		t.Fatalf("create domain: expected 201, got %d (%s)", dResp.StatusCode, b)
	}
	domainID := parseBody(t, dResp)["data"].(map[string]any)["domain"].(map[string]any)["id"].(string)
	mustClose(dResp)
	// Clean up the domain (cascades the provisioned mailbox) so this test does
	// not contribute to the shared dev DB's domain accumulation, which trips
	// the Free 3-domain cap in other suites.
	t.Cleanup(func() {
		_, _ = env.pool.Exec(context.Background(), "DELETE FROM domains WHERE id = $1", domainID)
	})

	// Mint a SCIM token.
	mResp := env.doRequest(t, "POST", "/api/v1/scim-tokens", "{}")
	token := parseBody(t, mResp)["data"].(map[string]any)["token"].(string)
	mustClose(mResp)

	userName := "alice@" + domainName
	extID := fmt.Sprintf("ext-alice-%d", time.Now().UnixNano())
	createBody := fmt.Sprintf(`{
		"schemas": [%q],
		"userName": %q,
		"externalId": %q,
		"name": {"formatted": "Alice Example"},
		"active": true
	}`, scimUserSchema, userName, extID)

	// Create → 201 + Location + id.
	cResp := scimReq(t, env, "POST", "/scim/v2/Users", token, createBody)
	if cResp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(cResp.Body)
		t.Fatalf("create user: expected 201, got %d (%s)", cResp.StatusCode, b)
	}
	created := parseBody(t, cResp)
	mustClose(cResp)
	userID, _ := created["id"].(string)
	if userID == "" {
		t.Fatalf("create user: missing id in %v", created)
	}
	if created["userName"] != userName {
		t.Errorf("userName = %v, want %s", created["userName"], userName)
	}
	if created["active"] != true {
		t.Errorf("active = %v, want true", created["active"])
	}
	if cResp.Header.Get("Location") == "" {
		t.Error("create user: missing Location header")
	}

	// Get by id.
	gResp := scimReq(t, env, "GET", "/scim/v2/Users/"+userID, token, "")
	if gResp.StatusCode != http.StatusOK {
		t.Fatalf("get user: expected 200, got %d", gResp.StatusCode)
	}
	if got := parseBody(t, gResp)["userName"]; got != userName {
		t.Errorf("get userName = %v, want %s", got, userName)
	}
	mustClose(gResp)

	// Filter by userName eq → ListResponse with 1 result.
	fResp := scimReq(t, env, "GET", "/scim/v2/Users?filter="+url.QueryEscape(`userName eq "`+userName+`"`), token, "")
	if fResp.StatusCode != http.StatusOK {
		t.Fatalf("filter: expected 200, got %d", fResp.StatusCode)
	}
	filtered := parseBody(t, fResp)
	mustClose(fResp)
	if tr, _ := filtered["totalResults"].(float64); tr != 1 {
		t.Errorf("filter totalResults = %v, want 1", filtered["totalResults"])
	}

	// Duplicate create (same userName) → 409 uniqueness.
	dupResp := scimReq(t, env, "POST", "/scim/v2/Users", token, createBody)
	if dupResp.StatusCode != http.StatusConflict {
		t.Errorf("duplicate create: expected 409, got %d", dupResp.StatusCode)
	}
	if st := parseBody(t, dupResp)["scimType"]; st != "uniqueness" {
		t.Errorf("duplicate scimType = %v, want uniqueness", st)
	}
	mustClose(dupResp)

	// PATCH active:false (Okta shape) → deactivate.
	patchBody := fmt.Sprintf(`{"schemas":[%q],"Operations":[{"op":"replace","path":"active","value":false}]}`, scimPatchOp)
	pResp := scimReq(t, env, "PATCH", "/scim/v2/Users/"+userID, token, patchBody)
	if pResp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(pResp.Body)
		t.Fatalf("patch: expected 200, got %d (%s)", pResp.StatusCode, b)
	}
	if act := parseBody(t, pResp)["active"]; act != false {
		t.Errorf("after patch active = %v, want false", act)
	}
	mustClose(pResp)

	// DELETE → 204; mailbox is deactivated (never erased), still fetchable.
	delResp := scimReq(t, env, "DELETE", "/scim/v2/Users/"+userID, token, "")
	if delResp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: expected 204, got %d", delResp.StatusCode)
	}
	mustClose(delResp)

	afterDel := scimReq(t, env, "GET", "/scim/v2/Users/"+userID, token, "")
	if afterDel.StatusCode != http.StatusOK {
		t.Fatalf("get after delete: expected 200 (deactivate-not-erase), got %d", afterDel.StatusCode)
	}
	if act := parseBody(t, afterDel)["active"]; act != false {
		t.Errorf("after delete active = %v, want false", act)
	}
	mustClose(afterDel)
}
