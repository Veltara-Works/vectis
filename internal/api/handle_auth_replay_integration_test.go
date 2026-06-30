//go:build integration

package api_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// TestTOTPCodeReplayRejected proves a TOTP code accepted once cannot be replayed
// within the validation skew window (#116/166). It drives the real two-step
// /auth/login flow against live Valkey: a code that succeeds on first
// presentation must be rejected on a second presentation through a fresh TOTP
// session. Mirrors the SAML assertion-replay integration test — the replay
// cache, not the validator, is what must reject the second use.
//
// Real-envelope: the code is generated from the same encrypted secret the server
// validates against, via a TOTPManager keyed identically to the server's
// (CookieSecret + Hostname from setupTestEnv).
func TestTOTPCodeReplayRejected(t *testing.T) {
	env := setupTestEnv(t)
	ctx := context.Background()

	// Enrol TOTP on the seeded admin. The manager key must match api.New's
	// (auth.NewTOTPManager(cfg.CookieSecret, cfg.Hostname)) so the encrypted
	// secret stored here decrypts under the server's manager.
	tm := auth.NewTOTPManager("test-secret-32-chars-minimum-1234", "test.example.com")
	encSecret, provURI, err := tm.GenerateSecret("totp-replay@example.com")
	if err != nil {
		t.Fatalf("generate TOTP secret: %v", err)
	}

	// Pull the base32 secret out of the otpauth:// provisioning URI so we can
	// mint live codes the server will accept.
	u, err := url.Parse(provURI)
	if err != nil {
		t.Fatalf("parse provisioning URI: %v", err)
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		t.Fatal("provisioning URI carried no secret")
	}

	adminRepo := repository.NewAdminRepo(env.pool)
	admin, err := adminRepo.GetByID(ctx, env.adminID)
	if err != nil || admin == nil {
		t.Fatalf("load seeded admin: %v", err)
	}
	enabled := true
	if _, err := adminRepo.Update(ctx, env.adminID, repository.AdminUpdate{
		TOTPSecret:  &encSecret,
		TOTPEnabled: &enabled,
	}); err != nil {
		t.Fatalf("enable TOTP on admin: %v", err)
	}

	// startTOTP runs login step 1 (password) and returns the pending TOTP
	// session token the second step needs.
	startTOTP := func() string {
		body := `{"email":"` + admin.Email + `","password":"test-password"}`
		resp := env.doRequest(t, "POST", "/api/v1/auth/login", body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("login step 1: status %d, want 200", resp.StatusCode)
		}
		data, ok := parseBody(t, resp)["data"].(map[string]any)
		if !ok {
			t.Fatal("login step 1: missing data envelope")
		}
		if data["requires_totp"] != true {
			t.Fatalf("login step 1: requires_totp = %v, want true", data["requires_totp"])
		}
		sess, _ := data["totp_session"].(string)
		if sess == "" {
			t.Fatal("login step 1: empty totp_session")
		}
		return sess
	}

	// Generate one code and use the SAME string for both presentations, so the
	// replay is rejected by the used-code cache rather than by the code simply
	// having rolled to a new period.
	code, err := totp.GenerateCode(secret, time.Now())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}

	// First presentation — must succeed.
	sess1 := startTOTP()
	resp1 := env.doRequest(t, "POST", "/api/v1/auth/login",
		`{"totp_session":"`+sess1+`","totp_code":"`+code+`"}`)
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first TOTP presentation: status %d, want 200", resp1.StatusCode)
	}
	resp1.Body.Close()

	// Second presentation of the SAME code through a fresh session — must be
	// rejected as a replay.
	sess2 := startTOTP()
	resp2 := env.doRequest(t, "POST", "/api/v1/auth/login",
		`{"totp_session":"`+sess2+`","totp_code":"`+code+`"}`)
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed TOTP code: status %d, want 401", resp2.StatusCode)
	}
	body2 := parseBody(t, resp2)
	if errObj, ok := body2["error"].(map[string]any); !ok || errObj["code"] != "TOTP_INVALID" {
		t.Fatalf("replayed TOTP code: error = %v, want code TOTP_INVALID", body2["error"])
	}
}
