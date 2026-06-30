package api

import (
	"context"
	"net/http"
	"strings"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// federatedIdentity is the provider-agnostic view of an authenticated SSO
// identity — OIDC ID-token claims or a verified SAML assertion — consumed by the
// shared admin-resolution logic.
type federatedIdentity struct {
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
}

// federatedLinker carries the provider-specific repository calls and the
// provider-named error strings the shared resolver needs.
type federatedLinker struct {
	codePrefix    string                                                           // "OIDC" or "SAML" — error-code namespace
	logLabel      string                                                           // "oidc" or "saml" — structured-log identifier
	getBySubject  func(context.Context, string, string) (*repository.Admin, error) // GetByOIDC / GetBySAML
	link          func(context.Context, string, string, string) error              // LinkOIDC / LinkSAML
	unverifiedMsg string                                                           // returned when the IdP asserts no usable verified email
	noAccountMsg  string                                                           // returned when no admin exists for the asserted email
}

// federatedOutcome is the result of resolving a federated identity to an admin.
// A zero code means success and the returned admin is non-nil.
type federatedOutcome struct {
	httpStatus int
	code       string
	message    string
}

// resolveFederatedAdmin maps a verified SSO identity to an existing admin,
// auto-linking the provider identity to an admin matched by email on first
// login. It is the single authoritative copy of the OIDC and SAML callback
// resolution flows (audit finding #159), so the verified-email guard added for
// OIDC in #117 can never again be present on one path and missing on the other
// (#172).
//
// Trust model: the email fallback auto-links an unrecognised provider subject to
// a pre-existing admin purely on the asserted address, so that address MUST be
// one the IdP vouches for. OIDC carries that as the email_verified claim; for
// SAML the assertion is signed by the operator-configured IdP, so the asserted
// email is vouched for by the signature itself (SAML has no separate
// email_verified attribute) and callers set EmailVerified=true. Either way an
// empty or malformed address is never trusted. The provider+subject path —
// already-linked admins — is unaffected and ignores EmailVerified entirely.
func (s *Server) resolveFederatedAdmin(ctx context.Context, ident federatedIdentity, fl federatedLinker) (*repository.Admin, federatedOutcome) {
	admin, err := fl.getBySubject(ctx, ident.Provider, ident.Subject)
	if err != nil {
		s.logger.Error(fl.logLabel+" admin lookup failed", "error", err)
		return nil, federatedOutcome{http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to look up admin"}
	}
	if admin != nil {
		return admin, federatedOutcome{} // already linked — no email trust required
	}

	// Unrecognised subject → fall back to email-based auto-link. Require an
	// IdP-vouched, well-formed address before trusting it to bind a session.
	email := strings.ToLower(strings.TrimSpace(ident.Email))
	if !ident.EmailVerified || !isLinkableEmail(email) {
		s.logger.Warn(fl.logLabel+" auto-link refused: no verified email asserted by IdP",
			"provider", ident.Provider, "subject", ident.Subject)
		return nil, federatedOutcome{http.StatusForbidden, fl.codePrefix + "_EMAIL_UNVERIFIED", fl.unverifiedMsg}
	}

	admin, err = s.admins.GetByEmail(ctx, email)
	if err != nil {
		s.logger.Error(fl.logLabel+" email lookup failed", "error", err)
		return nil, federatedOutcome{http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to look up admin"}
	}
	if admin == nil {
		return nil, federatedOutcome{http.StatusForbidden, fl.codePrefix + "_NO_ACCOUNT", fl.noAccountMsg}
	}

	if err := fl.link(ctx, admin.ID, ident.Provider, ident.Subject); err != nil {
		s.logger.Error(fl.logLabel+" link failed", "error", err, "admin_id", admin.ID)
		return nil, federatedOutcome{http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to link " + fl.codePrefix + " identity"}
	}
	s.logger.Info(fl.logLabel+" identity linked to admin", "admin_id", admin.ID, "provider", ident.Provider)
	return admin, federatedOutcome{}
}

// establishFederatedSession finishes a successful SSO login: it creates a
// session for the resolved admin (no TOTP — federated login trusts the IdP),
// sets the session cookie, records the login, audits it, and redirects to the
// admin UI. Shared by the OIDC and SAML callbacks so the post-resolution flow
// cannot drift either.
func (s *Server) establishFederatedSession(w http.ResponseWriter, r *http.Request, admin *repository.Admin, auditAction, provider string) {
	token, session, err := s.sessions.CreateSession(r.Context(), admin.ID, clientIP(r), r.UserAgent())
	if err != nil {
		s.logger.Error("create session after federated login failed", "error", err, "action", auditAction)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session")
		return
	}

	s.admins.UpdateLastLogin(r.Context(), admin.ID)
	s.setSessionCookie(w, token, session.ExpiresAt)

	ip := clientIP(r)
	s.audit.Log(r.Context(), &admin.ID, auditAction, "admin", &admin.ID,
		map[string]any{"provider": provider, "ip": ip}, &ip)

	http.Redirect(w, r, "/admin", http.StatusFound)
}

// isLinkableEmail reports whether an address has both a local part and a domain,
// i.e. is usable as an auto-link key. Reuses the send-path address splitters.
func isLinkableEmail(email string) bool {
	return extractLocalPart(email) != "" && extractDomain(email) != ""
}
