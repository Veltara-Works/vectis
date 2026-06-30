package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/valkey-io/valkey-go"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/ratelimit"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// sessionCookieName is the HMAC-signed session cookie set on login and cleared
// on logout. ADR-020 (signed cookies); the value is "token.signature".
const sessionCookieName = "vectis_session"

// setSessionCookie writes the signed session cookie with the standard security
// attributes (HttpOnly, Secure, SameSite=Strict). expires matches the
// server-side session lifetime. Shared by password, OIDC, and SAML login.
func (s *Server) setSessionCookie(w http.ResponseWriter, token string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    s.sessions.SignToken(token),
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  expires,
	})
}

// clearSessionCookie expires the session cookie using the same attributes as
// setSessionCookie — the browser only overwrites a cookie when they match.
func clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
}

// Credential-endpoint rate limits. chi's Throttle on the login route is a
// concurrency ceiling, not a rate limiter — it does nothing to stop sequential
// password/TOTP guessing. These Valkey-backed fixed windows bound brute force:
//   - per-IP: caps total /auth/login calls (step-1 password + step-2 TOTP)
//     from one address, so credential spray across accounts is bounded.
//   - per-email: caps attempts against a single account, keyed by the SUBMITTED
//     email (not the resolved admin ID) and applied to known and unknown emails
//     alike — so the 429 can't double as an account-existence oracle — which
//     also stops a distributed attacker grinding one account from many IPs.
//
// Limits are generous enough that a human admin (who logs in rarely) never
// trips them, but tight enough that brute force is impractical. All checks
// fail-OPEN on a Valkey error so an infra blip never locks out logins.
const (
	loginIPRateLimit    = 20
	loginIPRateWindow   = 5 * time.Minute
	loginAcctRateLimit  = 10
	loginAcctRateWindow = 15 * time.Minute
	totpAcctRateLimit   = 10
	totpAcctRateWindow  = 15 * time.Minute
)

// loginEmailKey derives a stable, privacy-preserving Valkey key fragment for a
// submitted login email: lowercased and trimmed so case/whitespace variants
// share one bucket (an attacker can't multiply their budget with casing games),
// then SHA-256 hex so the raw address is never stored in Valkey.
func loginEmailKey(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return hex.EncodeToString(sum[:])
}

// rateLimitOK records one hit against key's fixed window and, when the window
// is exhausted, writes a 429 with Retry-After and returns false. On a limiter
// (Valkey) error it logs and returns true — fail-open, so a Valkey outage can
// never lock admins out of their own panel. errCode is the API error code
// surfaced to the client.
func (s *Server) rateLimitOK(w http.ResponseWriter, r *http.Request, key string, limit int, window time.Duration, errCode string) bool {
	res, err := ratelimit.Allow(r.Context(), s.vk, key, limit, window)
	if err != nil {
		s.logger.Warn("login rate-limit check failed; allowing (fail-open)", "key", key, "error", err)
		return true
	}
	if !res.Allowed {
		retry := ratelimit.RetryAfter(r.Context(), s.vk, key, window)
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		respondError(w, r, http.StatusTooManyRequests, errCode, "Too many attempts; please try again later")
		return false
	}
	return true
}

type loginRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	TOTPSession string `json:"totp_session,omitempty"`
	TOTPCode    string `json:"totp_code,omitempty"`
}

type loginResponse struct {
	Admin     adminProfile `json:"admin"`
	SessionID string       `json:"session_id"`
	ExpiresAt time.Time    `json:"expires_at"`
}

type totpRequiredResponse struct {
	RequiresTOTP bool   `json:"requires_totp"`
	TOTPSession  string `json:"totp_session"`
}

type adminProfile struct {
	ID           string     `json:"id"`
	Email        string     `json:"email"`
	Role         string     `json:"role"`
	TOTPEnabled  bool       `json:"totp_enabled"`
	OIDCProvider *string    `json:"oidc_provider,omitempty"`
	SAMLProvider *string    `json:"saml_provider,omitempty"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
	// Tier + Features expose just enough license state for the admin UI to
	// render tier-aware affordances (e.g. priority-support link in the
	// account menu). The full /api/v1/license endpoint stays super_admin-
	// only because it returns sensitive subscription identifiers.
	Tier     string   `json:"tier"`
	Features []string `json:"features"`
}

type totpSetupResponse struct {
	ProvisioningURI string `json:"provisioning_uri"`
}

type totpVerifyRequest struct {
	Code string `json:"code"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	// Per-IP brute-force bound. Applied to every /auth/login call (covers both
	// the password step and the TOTP step below), so an attacker spraying
	// credentials from one address is cut off regardless of which account or
	// step they target.
	if !s.rateLimitOK(w, r, "ratelimit:login:ip:"+clientIP(r), loginIPRateLimit, loginIPRateWindow, "RATE_LIMITED") {
		return
	}

	// Step 2: TOTP verification (second call with totp_session + totp_code).
	if req.TOTPSession != "" && req.TOTPCode != "" {
		s.completeTOTPLogin(w, r, req.TOTPSession, req.TOTPCode)
		return
	}

	if req.Email == "" || req.Password == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "Email and password are required")
		return
	}

	// Per-email brute-force bound, keyed by a hash of the submitted email and
	// applied BEFORE the admin lookup so it covers existing and unknown emails
	// identically. A limiter keyed by the resolved admin ID would only ever trip
	// for real accounts, making its 429 an account-existence oracle that defeats
	// the timing equalization below (#179). Checked before the lookup, it also
	// sheds the DB query and (expensive) Argon2id verify under attack.
	if !s.rateLimitOK(w, r, "ratelimit:login:email:"+loginEmailKey(req.Email), loginAcctRateLimit, loginAcctRateWindow, "RATE_LIMITED") {
		return
	}

	// Look up admin.
	admin, err := s.admins.GetByEmail(r.Context(), req.Email)
	if err != nil {
		s.logger.Error("login lookup failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error")
		return
	}
	if admin == nil {
		// Equalize timing with the known-account path: run the same Argon2id
		// work a real password verify would before returning the identical
		// generic error, so response latency doesn't reveal whether the email
		// maps to a real admin (user enumeration, #179).
		auth.VerifyDummyPassword(req.Password)
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password")
		return
	}

	// Verify password.
	ok, err := auth.VerifyPassword(req.Password, admin.PasswordHash)
	if err != nil || !ok {
		// Log the attempt for audit.
		adminID := admin.ID
		ip := clientIP(r)
		s.audit.Log(r.Context(), &adminID, "auth.login", "admin", &adminID,
			map[string]any{"success": false, "ip": ip, "totp_used": false}, &ip)
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password")
		return
	}

	// If TOTP is enabled, return a temporary session token and require step 2.
	if admin.TOTPEnabled && admin.TOTPSecret != nil {
		totpSession, err := s.createTOTPSession(r.Context(), admin.ID)
		if err != nil {
			s.logger.Error("create TOTP session failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create TOTP session")
			return
		}
		respond(w, r, http.StatusOK, totpRequiredResponse{
			RequiresTOTP: true,
			TOTPSession:  totpSession,
		})
		return
	}

	// No TOTP — complete login directly.
	s.completeLogin(w, r, admin, false)
}

// completeTOTPLogin handles the second step of the login flow when TOTP is required.
func (s *Server) completeTOTPLogin(w http.ResponseWriter, r *http.Request, totpSession, totpCode string) {
	// Retrieve admin ID from TOTP session in Valkey.
	adminID, err := s.getTOTPSession(r.Context(), totpSession)
	if err != nil {
		respondError(w, r, http.StatusUnauthorized, "TOTP_SESSION_INVALID", "TOTP session expired or invalid")
		return
	}

	// Delete the TOTP session immediately (single-use).
	s.deleteTOTPSession(r.Context(), totpSession)

	admin, err := s.admins.GetByID(r.Context(), adminID)
	if err != nil || admin == nil {
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid credentials")
		return
	}

	if admin.TOTPSecret == nil {
		respondError(w, r, http.StatusBadRequest, "TOTP_NOT_CONFIGURED", "TOTP is not configured for this account")
		return
	}

	// Per-account bound on TOTP code attempts, keyed by admin ID. The per-IP
	// login limit already caps codes guessed from one address; this stops a
	// distributed attacker (who holds the password) from grinding the 6-digit
	// code space within the validation skew window across many IPs.
	if !s.rateLimitOK(w, r, "ratelimit:login:totp:"+admin.ID, totpAcctRateLimit, totpAcctRateWindow, "RATE_LIMITED") {
		return
	}

	// Validate the TOTP code.
	valid, err := s.totpManager.ValidateCodeWithSkew(*admin.TOTPSecret, totpCode)
	if err != nil || !valid {
		ip := clientIP(r)
		s.audit.Log(r.Context(), &admin.ID, "auth.login", "admin", &admin.ID,
			map[string]any{"success": false, "ip": ip, "totp_used": true, "totp_failed": true}, &ip)
		respondError(w, r, http.StatusUnauthorized, "TOTP_INVALID", "Invalid TOTP code")
		return
	}

	// Guard against replay within the validation skew window. A TOTP code stays
	// valid for period*(2*skew+1) = 90s, long enough for a code sniffed off the
	// wire (or read from a logged request) to be re-presented even under the
	// per-account rate limit above. Claim the code single-use; reject any second
	// presentation. Fails closed on a Valkey error (matching the SAML
	// assertion-replay guard) — the TOTP session GET above already proves Valkey
	// is reachable, so an error here is anomalous and must not silently disable
	// replay protection.
	fresh, err := s.claimTOTPCode(r.Context(), admin.ID, totpCode)
	if err != nil {
		s.logger.Error("TOTP replay-cache check failed; rejecting (fail-closed)", "error", err)
		respondError(w, r, http.StatusUnauthorized, "TOTP_INVALID", "Invalid TOTP code")
		return
	}
	if !fresh {
		ip := clientIP(r)
		s.audit.Log(r.Context(), &admin.ID, "auth.login", "admin", &admin.ID,
			map[string]any{"success": false, "ip": ip, "totp_used": true, "totp_replay": true}, &ip)
		respondError(w, r, http.StatusUnauthorized, "TOTP_INVALID", "Invalid TOTP code")
		return
	}

	s.completeLogin(w, r, admin, true)
}

// completeLogin creates a session, sets the cookie, and logs the audit event.
func (s *Server) completeLogin(w http.ResponseWriter, r *http.Request, admin *repository.Admin, totpUsed bool) {
	// Create session.
	token, session, err := s.sessions.CreateSession(r.Context(), admin.ID, clientIP(r), r.UserAgent())
	if err != nil {
		s.logger.Error("create session failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session")
		return
	}

	// Update last login.
	s.admins.UpdateLastLogin(r.Context(), admin.ID)

	// Set HMAC-signed session cookie (token value per ADR-020 / Spec B.6).
	s.setSessionCookie(w, token, session.ExpiresAt)

	// Audit log.
	ip := clientIP(r)
	s.audit.Log(r.Context(), &admin.ID, "auth.login", "admin", &admin.ID,
		map[string]any{"success": true, "ip": ip, "totp_used": totpUsed}, &ip)

	respond(w, r, http.StatusOK, loginResponse{
		Admin: adminProfile{
			ID:           admin.ID,
			Email:        admin.Email,
			Role:         admin.Role,
			TOTPEnabled:  admin.TOTPEnabled,
			OIDCProvider: admin.OIDCProvider,
			LastLoginAt:  admin.LastLoginAt,
		},
		SessionID: session.ID,
		ExpiresAt: session.ExpiresAt,
	})
}

// handleTOTPSetup generates a TOTP secret for the authenticated admin.
// The secret is stored encrypted but totp_enabled remains false until verified.
func (s *Server) handleTOTPSetup(w http.ResponseWriter, r *http.Request) {
	adminID := getAdminID(r.Context())

	admin, err := s.admins.GetByID(r.Context(), adminID)
	if err != nil || admin == nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve admin")
		return
	}

	if admin.TOTPEnabled {
		respondError(w, r, http.StatusConflict, "TOTP_ALREADY_ENABLED", "TOTP is already enabled; disable it first")
		return
	}

	encryptedSecret, provisioningURI, err := s.totpManager.GenerateSecret(admin.Email)
	if err != nil {
		s.logger.Error("TOTP generate failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate TOTP secret")
		return
	}

	// Store the encrypted secret with totp_enabled=false (enrolment started, not completed).
	enabled := false
	_, err = s.admins.Update(r.Context(), adminID, repository.AdminUpdate{
		TOTPSecret:  &encryptedSecret,
		TOTPEnabled: &enabled,
	})
	if err != nil {
		s.logger.Error("TOTP store secret failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to store TOTP secret")
		return
	}

	s.audit.Log(r.Context(), &adminID, "auth.totp.setup", "admin", &adminID, nil, nil)

	respond(w, r, http.StatusOK, totpSetupResponse{
		ProvisioningURI: provisioningURI,
	})
}

// handleTOTPVerify verifies a TOTP code and enables MFA for the admin.
func (s *Server) handleTOTPVerify(w http.ResponseWriter, r *http.Request) {
	adminID := getAdminID(r.Context())

	var req totpVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}
	if req.Code == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "TOTP code is required")
		return
	}

	admin, err := s.admins.GetByID(r.Context(), adminID)
	if err != nil || admin == nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve admin")
		return
	}

	if admin.TOTPSecret == nil {
		respondError(w, r, http.StatusBadRequest, "TOTP_NOT_CONFIGURED", "Call POST /auth/totp/setup first")
		return
	}

	if admin.TOTPEnabled {
		respondError(w, r, http.StatusConflict, "TOTP_ALREADY_ENABLED", "TOTP is already enabled")
		return
	}

	// Validate the code against the stored encrypted secret.
	valid, err := s.totpManager.ValidateCodeWithSkew(*admin.TOTPSecret, req.Code)
	if err != nil {
		s.logger.Error("TOTP validate failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate TOTP code")
		return
	}
	if !valid {
		respondError(w, r, http.StatusUnauthorized, "TOTP_INVALID", "Invalid TOTP code")
		return
	}

	// Enable TOTP.
	enabled := true
	_, err = s.admins.Update(r.Context(), adminID, repository.AdminUpdate{
		TOTPEnabled: &enabled,
	})
	if err != nil {
		s.logger.Error("TOTP enable failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to enable TOTP")
		return
	}

	s.audit.Log(r.Context(), &adminID, "auth.totp.enable", "admin", &adminID, nil, nil)

	respond(w, r, http.StatusOK, map[string]string{"message": "TOTP enabled successfully"})
}

// handleTOTPDisable disables TOTP for the authenticated admin.
// Requires the current TOTP code for verification (Spec A line 53).
func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	adminID := getAdminID(r.Context())

	var req totpVerifyRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}
	if req.Code == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "Current TOTP code is required to disable MFA")
		return
	}

	admin, err := s.admins.GetByID(r.Context(), adminID)
	if err != nil || admin == nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve admin")
		return
	}

	if !admin.TOTPEnabled || admin.TOTPSecret == nil {
		respondError(w, r, http.StatusBadRequest, "TOTP_NOT_ENABLED", "TOTP is not currently enabled")
		return
	}

	// Verify current TOTP code before disabling.
	valid, err := s.totpManager.ValidateCodeWithSkew(*admin.TOTPSecret, req.Code)
	if err != nil || !valid {
		respondError(w, r, http.StatusUnauthorized, "TOTP_INVALID", "Invalid TOTP code")
		return
	}

	// Clear secret and disable.
	emptySecret := ""
	enabled := false
	_, err = s.admins.Update(r.Context(), adminID, repository.AdminUpdate{
		TOTPSecret:  &emptySecret,
		TOTPEnabled: &enabled,
	})
	if err != nil {
		s.logger.Error("TOTP disable failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to disable TOTP")
		return
	}

	// Clear the empty string to NULL in DB for clean state.
	s.db.Exec(r.Context(), `UPDATE admins SET totp_secret = NULL WHERE id = $1`, adminID)

	s.audit.Log(r.Context(), &adminID, "auth.totp.disable", "admin", &adminID, nil, nil)

	respond(w, r, http.StatusOK, map[string]string{"message": "TOTP disabled successfully"})
}

// handleMe returns the current admin's profile including role.
func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	admin, err := s.admins.GetByID(r.Context(), getAdminID(r.Context()))
	if err != nil || admin == nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get admin profile")
		return
	}
	tier, features := s.currentTierAndFeatures(r.Context())
	respond(w, r, http.StatusOK, adminProfile{
		ID:           admin.ID,
		Email:        admin.Email,
		Role:         admin.Role,
		TOTPEnabled:  admin.TOTPEnabled,
		OIDCProvider: admin.OIDCProvider,
		SAMLProvider: admin.SAMLProvider,
		LastLoginAt:  admin.LastLoginAt,
		Tier:         tier,
		Features:     features,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r.Context())
	if err := s.sessions.DeleteSession(r.Context(), sessionID); err != nil {
		s.logger.Error("logout failed", "error", err)
	}

	clearSessionCookie(w)

	respond(w, r, http.StatusOK, map[string]string{"message": "Logged out"})
}

func (s *Server) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	adminID := getAdminID(r.Context())
	if err := s.sessions.DeleteAllSessions(r.Context(), adminID); err != nil {
		s.logger.Error("logout-all failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to invalidate sessions")
		return
	}

	clearSessionCookie(w)

	respond(w, r, http.StatusOK, map[string]string{"message": "All sessions invalidated"})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	adminID := getAdminID(r.Context())
	sessions, err := s.sessions.ListSessions(r.Context(), adminID)
	if err != nil {
		s.logger.Error("list sessions failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list sessions")
		return
	}
	respond(w, r, http.StatusOK, sessions)
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	// Scope the delete to the caller's own sessions: an admin must not be able
	// to revoke another admin's session by guessing/enumerating its ID (IDOR).
	deleted, err := s.sessions.DeleteSessionForAdmin(r.Context(), sessionID, getAdminID(r.Context()))
	if err != nil {
		s.logger.Error("delete session failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete session")
		return
	}
	if !deleted {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Session not found")
		return
	}
	respond(w, r, http.StatusOK, map[string]string{"message": "Session invalidated"})
}

// createTOTPSession stores a temporary token in Valkey that maps to an admin ID.
// This is used for the two-step login flow: password verified, TOTP pending.
// TTL is 5 minutes — if the user doesn't provide a TOTP code in time, they must re-authenticate.
func (s *Server) createTOTPSession(ctx context.Context, adminID string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", fmt.Errorf("generate TOTP session token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes)

	cmd := s.vk.B().Set().Key("totp_session:" + token).Value(adminID).Ex(5 * time.Minute).Build()
	if err := s.vk.Do(ctx, cmd).Error(); err != nil {
		return "", fmt.Errorf("store TOTP session: %w", err)
	}
	return token, nil
}

// totpReplayTTL bounds how long a used TOTP code is remembered. A code passes
// validation across the skew window — period*(2*skew+1) = 30s*3 = 90s — so
// remembering it for that span blocks replay until it can no longer validate
// anyway. Keeping the TTL tight stops the namespace from growing unbounded.
const totpReplayTTL = 90 * time.Second

// claimTOTPCode atomically marks a TOTP code single-use for an admin and reports
// whether this was its first presentation. SET NX lets the first use through; a
// later SET NX against the still-live key returns valkey.Nil, which we surface
// as "not fresh" (a replay). Any other Valkey error is returned so the caller
// can fail closed rather than silently skip replay protection.
func (s *Server) claimTOTPCode(ctx context.Context, adminID, code string) (bool, error) {
	cmd := s.vk.B().Set().Key("totp_used:" + adminID + ":" + code).Value("1").Nx().Ex(totpReplayTTL).Build()
	if err := s.vk.Do(ctx, cmd).Error(); err != nil {
		if valkey.IsValkeyNil(err) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// getTOTPSession retrieves the admin ID for a TOTP session token from Valkey.
func (s *Server) getTOTPSession(ctx context.Context, token string) (string, error) {
	cmd := s.vk.B().Get().Key("totp_session:" + token).Build()
	result, err := s.vk.Do(ctx, cmd).ToString()
	if err != nil {
		return "", fmt.Errorf("TOTP session not found: %w", err)
	}
	return result, nil
}

// deleteTOTPSession removes a TOTP session token from Valkey.
func (s *Server) deleteTOTPSession(ctx context.Context, token string) {
	cmd := s.vk.B().Del().Key("totp_session:" + token).Build()
	s.vk.Do(ctx, cmd)
}
