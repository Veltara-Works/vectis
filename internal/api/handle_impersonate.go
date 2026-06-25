package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	impersonationTTL   = 30 * time.Minute
	impersonatePurpose = "impersonate"
)

type impersonateResponse struct {
	IMAPHost   string `json:"imap_host"`
	IMAPPort   int    `json:"imap_port"`
	Username   string `json:"username"` // the mailbox's own address — log in AS this
	Password   string `json:"password"` // short-lived Dovecot auth-token password
	ExpiresAt  string `json:"expires_at"`
	ExpiresInS int    `json:"expires_in_seconds"`
}

// handleImpersonate mints a short-lived Dovecot auth token so an admin can log
// into a mailbox AS that user — the same token-passdb mechanism the native IMAP
// importer uses (internal/repository/dovecot_auth_token.go, migration 000023).
// The admin connects to IMAP as the mailbox's own address with the returned
// token password; the auth_token passdb is checked before the real mailbox
// passdb and is fail-safe (a miss/expiry/DB error falls through to normal auth).
// Tokens expire after 30 minutes and every impersonation is audit-logged.
func (s *Server) handleImpersonate(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	if mailboxID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_ID", "Mailbox ID is required")
		return
	}

	// Fetch the mailbox.
	mailbox, err := s.mailboxes.GetByID(r.Context(), mailboxID)
	if err != nil {
		s.logger.Error("get mailbox for impersonation failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get mailbox")
		return
	}
	if mailbox == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Mailbox not found")
		return
	}

	// RBAC: check domain access.
	if !s.canAccessDomain(r.Context(), mailbox.DomainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this mailbox")
		return
	}

	// Get domain for building the email address.
	domain, err := s.domains.GetByID(r.Context(), mailbox.DomainID)
	if err != nil || domain == nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}

	userEmail := mailbox.LocalPart + "@" + domain.Name

	// Mint a short-lived auth token scoped to this mailbox. The admin logs into
	// Dovecot as userEmail with this token password.
	token, err := s.dovecotTokens.Mint(r.Context(), userEmail, impersonatePurpose, impersonationTTL)
	if err != nil {
		s.logger.Error("mint impersonation token failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate credentials")
		return
	}

	// Audit log — impersonation is a sensitive action.
	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "mailbox.impersonate", "mailbox", &mailboxID,
		map[string]any{
			"target_email": userEmail,
			"domain":       domain.Name,
			"token_id":     token.ID,
			"expires_at":   token.ExpiresAt.Format(time.RFC3339),
		}, &ip)

	respond(w, r, http.StatusOK, impersonateResponse{
		IMAPHost:   s.hostname,
		IMAPPort:   993,
		Username:   userEmail,
		Password:   token.Password,
		ExpiresAt:  token.ExpiresAt.Format(time.RFC3339),
		ExpiresInS: int(impersonationTTL.Seconds()),
	})
}

// handleRevokeImpersonation immediately invalidates all active impersonation
// tokens for a mailbox (deletes the rows). The importer's own "import"-purpose
// tokens for the same mailbox are left untouched.
func (s *Server) handleRevokeImpersonation(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	if mailboxID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_ID", "Mailbox ID is required")
		return
	}

	mailbox, err := s.mailboxes.GetByID(r.Context(), mailboxID)
	if err != nil || mailbox == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Mailbox not found")
		return
	}

	if !s.canAccessDomain(r.Context(), mailbox.DomainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this mailbox")
		return
	}

	domain, err := s.domains.GetByID(r.Context(), mailbox.DomainID)
	if err != nil || domain == nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}

	userEmail := mailbox.LocalPart + "@" + domain.Name
	if _, err := s.dovecotTokens.RevokeByTarget(r.Context(), userEmail, impersonatePurpose); err != nil {
		s.logger.Error("revoke impersonation tokens failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke credentials")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "mailbox.impersonate_revoke", "mailbox", &mailboxID,
		map[string]any{"target_email": userEmail}, &ip)

	respond(w, r, http.StatusOK, map[string]string{"status": "revoked"})
}
