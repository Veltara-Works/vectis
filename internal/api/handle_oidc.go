package api

import (
	"crypto/subtle"
	"net/http"

	"github.com/Veltara-Works/vectis/internal/validonx"
	"github.com/go-chi/chi/v5"
)

// oidcStateCookieName holds the OIDC `state` bound to the initiating browser.
const oidcStateCookieName = "vectis_oidc_state"

// setOIDCStateCookie binds the OIDC `state` to the browser that started the flow
// (OIDC-1). The server-side state store (atomic GETDEL) gives replay/single-use
// integrity but NOT session-binding, so without this a login-CSRF is possible:
// an attacker starts their own auth flow and tricks a victim's browser into
// completing the callback with the attacker's state, silently swapping the
// victim into the attacker's linked identity. handleOIDCCallback requires this
// cookie to equal the state query parameter.
//
// SameSite=Lax (not Strict like the session cookie): the callback is a
// cross-site top-level GET navigation from the IdP, on which a Strict cookie
// would not be sent. Lax still blocks the CSRF — the attacker cannot plant a
// cookie for our origin in the victim's browser. Scoped to the OIDC path with a
// short TTL bounding the auth round-trip.
func setOIDCStateCookie(w http.ResponseWriter, state string) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    state,
		Path:     "/api/v1/auth/oidc/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   600,
	})
}

// clearOIDCStateCookie expires the state cookie (single-use) with matching
// attributes so the browser overwrites it.
func clearOIDCStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oidcStateCookieName,
		Value:    "",
		Path:     "/api/v1/auth/oidc/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// handleOIDCProviders returns the list of enabled OIDC providers.
// Used by the frontend to render SSO login buttons.
//
// On Free-tier installs (ValidonX unconfigured OR licensed but not entitled
// to oidc_sso) the list is suppressed to an empty array, so the Login page
// silently omits SSO buttons rather than showing buttons that would 402/403
// on click. The /auth/oidc/login and /auth/oidc/callback routes carry their
// own FeatureGateBrowser as defence in depth — both surfaces deny on Free
// tier since v0.1.6 (pre-v0.1.6 the unconfigured branch passed through).
func (s *Server) handleOIDCProviders(w http.ResponseWriter, r *http.Request) {
	if s.oidcManager == nil || !s.oidcManager.HasProviders() {
		respond(w, r, http.StatusOK, map[string]any{"providers": []string{}})
		return
	}
	if !s.featureGate.HasFeature(r.Context(), validonx.FeatureOIDCSSO) {
		respond(w, r, http.StatusOK, map[string]any{"providers": []string{}})
		return
	}
	respond(w, r, http.StatusOK, map[string]any{"providers": s.oidcManager.ListProviders()})
}

// handleOIDCLogin initiates the OIDC authorization flow by redirecting the
// user to the provider's login page.
func (s *Server) handleOIDCLogin(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")

	if s.oidcManager == nil {
		respondError(w, r, http.StatusNotFound, "OIDC_NOT_CONFIGURED", "OIDC is not configured")
		return
	}

	provider := s.oidcManager.GetProvider(providerName)
	if provider == nil {
		respondError(w, r, http.StatusNotFound, "OIDC_PROVIDER_NOT_FOUND",
			"OIDC provider not found or not enabled")
		return
	}

	state, err := s.oidcManager.CreateState(r.Context(), providerName)
	if err != nil {
		s.logger.Error("create oidc state failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create OIDC state")
		return
	}

	// Bind the state to this browser so the callback can prove it originated the
	// flow (OIDC-1 login-CSRF defense).
	setOIDCStateCookie(w, state)

	authURL := provider.OAuth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusFound)
}

// handleOIDCCallback handles the OIDC provider redirect after authentication.
// It exchanges the authorization code for tokens, verifies the ID token,
// matches or links the identity to an existing admin, and creates a session.
func (s *Server) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")

	if s.oidcManager == nil {
		respondError(w, r, http.StatusNotFound, "OIDC_NOT_CONFIGURED", "OIDC is not configured")
		return
	}

	// Validate state (CSRF protection).
	state := r.URL.Query().Get("state")
	if state == "" {
		respondError(w, r, http.StatusBadRequest, "OIDC_MISSING_STATE", "Missing state parameter")
		return
	}

	// Browser binding (OIDC-1): the callback must carry the same state in the
	// cookie set at login. This is what turns state into a CSRF token rather than
	// just a replay nonce — the server-side GETDEL below can't tell whose browser
	// is completing the flow. Cleared unconditionally (single-use).
	stateCookie, _ := r.Cookie(oidcStateCookieName)
	clearOIDCStateCookie(w)
	if stateCookie == nil ||
		subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(state)) != 1 {
		respondError(w, r, http.StatusBadRequest, "OIDC_INVALID_STATE", "Invalid or expired state")
		return
	}

	validatedProvider, err := s.oidcManager.ValidateState(r.Context(), state)
	if err != nil {
		respondError(w, r, http.StatusBadRequest, "OIDC_INVALID_STATE", "Invalid or expired state")
		return
	}

	if validatedProvider != providerName {
		respondError(w, r, http.StatusBadRequest, "OIDC_STATE_MISMATCH", "State does not match provider")
		return
	}

	// Check for error from provider.
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		desc := r.URL.Query().Get("error_description")
		s.logger.Warn("oidc provider returned error", "provider", providerName, "error", errParam, "description", desc)
		respondError(w, r, http.StatusUnauthorized, "OIDC_PROVIDER_ERROR",
			"Authentication failed: "+errParam)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		respondError(w, r, http.StatusBadRequest, "OIDC_MISSING_CODE", "Missing authorization code")
		return
	}

	provider := s.oidcManager.GetProvider(providerName)
	if provider == nil {
		respondError(w, r, http.StatusNotFound, "OIDC_PROVIDER_NOT_FOUND", "Provider not found")
		return
	}

	// Exchange code and verify ID token.
	identity, err := s.oidcManager.ExchangeAndVerify(r.Context(), provider, code)
	if err != nil {
		s.logger.Error("oidc token exchange/verify failed", "provider", providerName, "error", err)
		respondError(w, r, http.StatusUnauthorized, "OIDC_AUTH_FAILED",
			"Failed to verify identity with provider")
		return
	}

	// Resolve the identity to an admin (auto-linking by verified email on first
	// login). Shared with the SAML ACS via resolveFederatedAdmin so the
	// verified-email guard cannot drift between the two paths (#159/#172).
	admin, out := s.resolveFederatedAdmin(r.Context(), federatedIdentity{
		Provider:      identity.Provider,
		Subject:       identity.Subject,
		Email:         identity.Email,
		EmailVerified: identity.EmailVerified,
	}, federatedLinker{
		codePrefix:   "OIDC",
		logLabel:     "oidc",
		getBySubject: s.admins.GetByOIDC,
		link:         s.admins.LinkOIDC,
		unverifiedMsg: "Your identity provider did not assert a verified email, so this account " +
			"cannot be auto-linked. Ask a super_admin to link your OIDC identity, " +
			"or configure the IdP to send email_verified=true.",
		noAccountMsg: "No admin account exists for this email. Ask a super_admin to create one first.",
	})
	if out.code != "" {
		respondError(w, r, out.httpStatus, out.code, out.message)
		return
	}

	// Create session (same as password login — no TOTP required for OIDC).
	s.establishFederatedSession(w, r, admin, "auth.oidc.login", identity.Provider)
}

// handleOIDCDisconnect unlinks the OIDC identity from the current admin's account.
// The admin must have a password set to disconnect (otherwise they'd be locked out).
func (s *Server) handleOIDCDisconnect(w http.ResponseWriter, r *http.Request) {
	adminID := getAdminID(r.Context())

	admin, err := s.admins.GetByID(r.Context(), adminID)
	if err != nil || admin == nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve admin")
		return
	}

	if admin.OIDCProvider == nil {
		respondError(w, r, http.StatusBadRequest, "OIDC_NOT_LINKED", "No OIDC provider is linked to this account")
		return
	}

	// Require password to be set before disconnecting OIDC (prevent lockout).
	if admin.PasswordHash == "" {
		respondError(w, r, http.StatusConflict, "OIDC_ONLY_ACCOUNT",
			"Set a password before disconnecting OIDC to avoid being locked out")
		return
	}

	if err := s.admins.UnlinkOIDC(r.Context(), adminID); err != nil {
		s.logger.Error("oidc unlink failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to disconnect OIDC")
		return
	}

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "auth.oidc.disconnect", "admin", &adminID,
		map[string]any{"provider": *admin.OIDCProvider}, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "OIDC provider disconnected"})
}
