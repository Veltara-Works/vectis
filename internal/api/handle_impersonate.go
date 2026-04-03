package api

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	impersonationTTL    = 30 * time.Minute
	impersonationPrefix = "impersonate:"
)

type impersonateResponse struct {
	IMAPHost    string `json:"imap_host"`
	IMAPPort    int    `json:"imap_port"`
	Username    string `json:"username"`     // master user format: user@domain*admin
	Password    string `json:"password"`     // temporary password
	ExpiresAt   string `json:"expires_at"`
	ExpiresInS  int    `json:"expires_in_seconds"`
}

// handleImpersonate generates temporary Dovecot master user credentials
// for an admin to access a mailbox. The credentials expire after 30 minutes.
// All impersonation is logged in the audit trail.
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

	// Generate a temporary password and store in Valkey.
	tempPassword, err := generateTempPassword()
	if err != nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate credentials")
		return
	}

	userEmail := mailbox.LocalPart + "@" + domain.Name
	masterUsername := userEmail + "*vectis-admin"

	// Store the temporary password in Valkey with TTL.
	vkKey := impersonationPrefix + masterUsername
	setCmd := s.vk.B().Set().Key(vkKey).Value(tempPassword).Ex(impersonationTTL).Build()
	if err := s.vk.Do(r.Context(), setCmd).Error(); err != nil {
		s.logger.Error("store impersonation creds failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to store credentials")
		return
	}

	expiresAt := time.Now().UTC().Add(impersonationTTL)

	// Audit log — impersonation is a sensitive action.
	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "mailbox.impersonate", "mailbox", &mailboxID,
		map[string]any{
			"target_email": userEmail,
			"domain":       domain.Name,
			"expires_at":   expiresAt.Format(time.RFC3339),
		}, &ip)

	respond(w, r, http.StatusOK, impersonateResponse{
		IMAPHost:   s.hostname,
		IMAPPort:   993,
		Username:   masterUsername,
		Password:   tempPassword,
		ExpiresAt:  expiresAt.Format(time.RFC3339),
		ExpiresInS: int(impersonationTTL.Seconds()),
	})
}

// handleRevokeImpersonation immediately invalidates impersonation credentials for a mailbox.
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
	masterUsername := userEmail + "*vectis-admin"
	vkKey := impersonationPrefix + masterUsername

	s.vk.Do(r.Context(), s.vk.B().Del().Key(vkKey).Build())

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "mailbox.impersonate_revoke", "mailbox", &mailboxID,
		map[string]any{"target_email": userEmail}, &ip)

	respond(w, r, http.StatusOK, map[string]string{"status": "revoked"})
}

func generateTempPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate temp password: %w", err)
	}
	return hex.EncodeToString(b), nil
}
