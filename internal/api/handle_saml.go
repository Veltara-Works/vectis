package api

import (
	"net/http"
	"strings"

	"github.com/Veltara-Works/vectis/internal/validonx"
	"github.com/go-chi/chi/v5"
)

// handleSAMLProviders returns the list of enabled SAML providers for rendering
// SSO login buttons. On installs not entitled to saml_sso (Free/Pro, or
// ValidonX unconfigured) the list is suppressed to an empty array, so the Login
// page omits SAML buttons rather than showing ones that would 402/403 on click.
// The login + ACS routes carry their own FeatureGateBrowser as defence in depth.
func (s *Server) handleSAMLProviders(w http.ResponseWriter, r *http.Request) {
	if s.samlManager == nil || !s.samlManager.HasProviders() {
		respond(w, r, http.StatusOK, map[string]any{"providers": []string{}})
		return
	}
	if !s.featureGate.HasFeature(r.Context(), validonx.FeatureSAMLSSO) {
		respond(w, r, http.StatusOK, map[string]any{"providers": []string{}})
		return
	}
	respond(w, r, http.StatusOK, map[string]any{"providers": s.samlManager.ListProviders()})
}

// handleSAMLMetadata serves the SP metadata XML for a provider. The operator
// hands this to their IdP. It contains no secrets — entityID, ACS URL, and the
// SP public certificate. Public (not feature-gated) so an operator can fetch it
// while configuring their IdP before flows are exercised.
func (s *Server) handleSAMLMetadata(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")

	if s.samlManager == nil {
		respondError(w, r, http.StatusNotFound, "SAML_NOT_CONFIGURED", "SAML is not configured")
		return
	}
	provider := s.samlManager.GetProvider(providerName)
	if provider == nil {
		respondError(w, r, http.StatusNotFound, "SAML_PROVIDER_NOT_FOUND", "SAML provider not found or not enabled")
		return
	}

	md, err := provider.MetadataXML()
	if err != nil {
		s.logger.Error("saml metadata marshal failed", "provider", providerName, "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to build SP metadata")
		return
	}

	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(md)
}

// handleSAMLLogin initiates SP-initiated SSO: it builds a signed AuthnRequest,
// stores RelayState in Valkey, and redirects the browser to the IdP.
func (s *Server) handleSAMLLogin(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")

	if s.samlManager == nil {
		respondError(w, r, http.StatusNotFound, "SAML_NOT_CONFIGURED", "SAML is not configured")
		return
	}
	provider := s.samlManager.GetProvider(providerName)
	if provider == nil {
		respondError(w, r, http.StatusNotFound, "SAML_PROVIDER_NOT_FOUND", "SAML provider not found or not enabled")
		return
	}

	redirectURL, err := s.samlManager.BuildAuthnRedirect(r.Context(), provider)
	if err != nil {
		s.logger.Error("saml authn request failed", "provider", providerName, "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to start SAML login")
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

// handleSAMLACS is the Assertion Consumer Service (HTTP-POST binding). It
// validates the assertion, maps it to a pre-existing admin (no JIT
// provisioning, same as OIDC), and creates a session.
func (s *Server) handleSAMLACS(w http.ResponseWriter, r *http.Request) {
	providerName := chi.URLParam(r, "provider")

	if s.samlManager == nil {
		respondError(w, r, http.StatusNotFound, "SAML_NOT_CONFIGURED", "SAML is not configured")
		return
	}
	provider := s.samlManager.GetProvider(providerName)
	if provider == nil {
		respondError(w, r, http.StatusNotFound, "SAML_PROVIDER_NOT_FOUND", "Provider not found")
		return
	}

	// Validate the assertion: signature, audience, time window, recipient,
	// InResponseTo, RelayState (CSRF), and single-use replay protection.
	identity, err := s.samlManager.ParseAndVerifyAssertion(r.Context(), provider, r)
	if err != nil {
		s.logger.Warn("saml assertion validation failed", "provider", providerName, "error", err)
		respondError(w, r, http.StatusUnauthorized, "SAML_AUTH_FAILED", "Failed to verify SAML assertion")
		return
	}

	// Look up admin: first by SAML identity (provider+subject), then by email.
	admin, err := s.admins.GetBySAML(r.Context(), identity.Provider, identity.Subject)
	if err != nil {
		s.logger.Error("saml admin lookup failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to look up admin")
		return
	}

	if admin == nil {
		admin, err = s.admins.GetByEmail(r.Context(), strings.ToLower(identity.Email))
		if err != nil {
			s.logger.Error("saml email lookup failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to look up admin")
			return
		}
		if admin == nil {
			respondError(w, r, http.StatusForbidden, "SAML_NO_ACCOUNT",
				"No admin account exists for this email. Ask a super_admin to create one first.")
			return
		}
		if err := s.admins.LinkSAML(r.Context(), admin.ID, identity.Provider, identity.Subject); err != nil {
			s.logger.Error("saml link failed", "error", err, "admin_id", admin.ID)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to link SAML identity")
			return
		}
		s.logger.Info("saml identity linked to admin", "admin_id", admin.ID, "provider", identity.Provider)
	}

	// Create session (federated — no TOTP required, same as OIDC).
	token, session, err := s.sessions.CreateSession(r.Context(), admin.ID, clientIP(r), r.UserAgent())
	if err != nil {
		s.logger.Error("create session after saml login failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session")
		return
	}

	s.admins.UpdateLastLogin(r.Context(), admin.ID)

	signedToken := s.sessions.SignToken(token)
	http.SetCookie(w, &http.Cookie{
		Name:     "vectis_session",
		Value:    signedToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  session.ExpiresAt,
	})

	ip := clientIP(r)
	s.audit.Log(r.Context(), &admin.ID, "auth.saml.login", "admin", &admin.ID,
		map[string]any{"provider": identity.Provider, "ip": ip}, &ip)

	http.Redirect(w, r, "/admin", http.StatusFound)
}

// handleSAMLDisconnect unlinks the SAML identity from the current admin. The
// admin must have a password set first, to avoid being locked out.
func (s *Server) handleSAMLDisconnect(w http.ResponseWriter, r *http.Request) {
	adminID := getAdminID(r.Context())

	admin, err := s.admins.GetByID(r.Context(), adminID)
	if err != nil || admin == nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to retrieve admin")
		return
	}

	if admin.SAMLProvider == nil {
		respondError(w, r, http.StatusBadRequest, "SAML_NOT_LINKED", "No SAML provider is linked to this account")
		return
	}

	if admin.PasswordHash == "" {
		respondError(w, r, http.StatusConflict, "SAML_ONLY_ACCOUNT",
			"Set a password before disconnecting SAML to avoid being locked out")
		return
	}

	if err := s.admins.UnlinkSAML(r.Context(), adminID); err != nil {
		s.logger.Error("saml unlink failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to disconnect SAML")
		return
	}

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "auth.saml.disconnect", "admin", &adminID,
		map[string]any{"provider": *admin.SAMLProvider}, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "SAML provider disconnected"})
}
