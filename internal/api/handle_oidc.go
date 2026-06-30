package api

import (
	"net/http"
	"strings"

	"github.com/Veltara-Works/vectis/internal/validonx"
	"github.com/go-chi/chi/v5"
)

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

	// Look up admin: first by OIDC identity (provider+subject), then by email.
	admin, err := s.admins.GetByOIDC(r.Context(), identity.Provider, identity.Subject)
	if err != nil {
		s.logger.Error("oidc admin lookup failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to look up admin")
		return
	}

	if admin == nil {
		// Falling back to email-based matching auto-links a new IdP subject to
		// an existing admin account. The email claim is attacker-controllable
		// at IdPs that emit unverified emails (multi-tenant/consumer providers),
		// so we MUST require a verified email here — otherwise an attacker who
		// can assert a super_admin's address gets a silent link + full session.
		// The provider+subject path above is unaffected: already-linked admins
		// keep logging in regardless of the email_verified claim.
		if !identity.EmailVerified {
			s.logger.Warn("oidc auto-link refused: email not verified by IdP",
				"provider", identity.Provider, "subject", identity.Subject)
			respondError(w, r, http.StatusForbidden, "OIDC_EMAIL_UNVERIFIED",
				"Your identity provider did not assert a verified email, so this account "+
					"cannot be auto-linked. Ask a super_admin to link your OIDC identity, "+
					"or configure the IdP to send email_verified=true.")
			return
		}

		// Try matching by email — auto-link if admin exists.
		admin, err = s.admins.GetByEmail(r.Context(), strings.ToLower(identity.Email))
		if err != nil {
			s.logger.Error("oidc email lookup failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to look up admin")
			return
		}

		if admin == nil {
			// No matching admin — OIDC login requires a pre-existing admin account.
			respondError(w, r, http.StatusForbidden, "OIDC_NO_ACCOUNT",
				"No admin account exists for this email. Ask a super_admin to create one first.")
			return
		}

		// Link the OIDC identity to this admin.
		if err := s.admins.LinkOIDC(r.Context(), admin.ID, identity.Provider, identity.Subject); err != nil {
			s.logger.Error("oidc link failed", "error", err, "admin_id", admin.ID)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to link OIDC identity")
			return
		}
		s.logger.Info("oidc identity linked to admin", "admin_id", admin.ID, "provider", identity.Provider)
	}

	// Create session (same as password login — no TOTP required for OIDC).
	token, session, err := s.sessions.CreateSession(r.Context(), admin.ID, clientIP(r), r.UserAgent())
	if err != nil {
		s.logger.Error("create session after oidc login failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session")
		return
	}

	s.admins.UpdateLastLogin(r.Context(), admin.ID)

	s.setSessionCookie(w, token, session.ExpiresAt)

	// Audit log.
	ip := clientIP(r)
	s.audit.Log(r.Context(), &admin.ID, "auth.oidc.login", "admin", &admin.ID,
		map[string]any{"provider": identity.Provider, "ip": ip}, &ip)

	// Redirect to admin UI after successful login.
	http.Redirect(w, r, "/admin", http.StatusFound)
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
