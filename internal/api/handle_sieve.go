package api

import (
	"fmt"
	"net/http"

	"github.com/go-chi/chi/v5"
)

type sieveScriptRequest struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Active  bool   `json:"active,omitempty"`
}

// handleListSieveScripts returns all Sieve filter scripts for a mailbox.
func (s *Server) handleListSieveScripts(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	user, pass, err := s.getMailboxCredentials(r, mailboxID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}

	if s.sieveClient == nil {
		respondError(w, r, http.StatusServiceUnavailable, "SIEVE_UNAVAILABLE", "Sieve filtering is not configured")
		return
	}

	scripts, err := s.sieveClient.ListScripts(user, pass)
	if err != nil {
		s.logger.Error("list sieve scripts failed", "error", err, "mailbox_id", mailboxID)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list filter scripts")
		return
	}

	respond(w, r, http.StatusOK, scripts)
}

// handleGetSieveScript returns the content of a named Sieve script.
func (s *Server) handleGetSieveScript(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	scriptName := chi.URLParam(r, "scriptName")
	user, pass, err := s.getMailboxCredentials(r, mailboxID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}

	content, err := s.sieveClient.GetScript(user, pass, scriptName)
	if err != nil {
		s.logger.Error("get sieve script failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get filter script")
		return
	}

	respond(w, r, http.StatusOK, map[string]string{"name": scriptName, "content": content})
}

// handlePutSieveScript creates or updates a Sieve script.
func (s *Server) handlePutSieveScript(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")

	var req sieveScriptRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}
	if req.Name == "" || req.Content == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "name and content are required")
		return
	}

	user, pass, err := s.getMailboxCredentials(r, mailboxID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}

	if err := s.sieveClient.PutScript(user, pass, req.Name, req.Content); err != nil {
		s.logger.Error("put sieve script failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save filter script: "+err.Error())
		return
	}

	if req.Active {
		if err := s.sieveClient.SetActive(user, pass, req.Name); err != nil {
			s.logger.Error("activate sieve script failed", "error", err)
		}
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "sieve.update", "mailbox", &mailboxID,
		map[string]any{"script": req.Name, "active": req.Active}, &ip)

	respond(w, r, http.StatusOK, map[string]string{"status": "saved", "name": req.Name})
}

// handleDeleteSieveScript removes a Sieve script.
func (s *Server) handleDeleteSieveScript(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	scriptName := chi.URLParam(r, "scriptName")
	user, pass, err := s.getMailboxCredentials(r, mailboxID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}

	if err := s.sieveClient.DeleteScript(user, pass, scriptName); err != nil {
		s.logger.Error("delete sieve script failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete filter script")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "sieve.delete", "mailbox", &mailboxID,
		map[string]any{"script": scriptName}, &ip)

	respond(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

// getMailboxCredentials resolves a mailbox ID to user@domain + password for ManageSieve auth.
// In admin impersonation mode, uses a master password via Dovecot master user mechanism.
func (s *Server) getMailboxCredentials(r *http.Request, mailboxID string) (string, string, error) {
	mailbox, err := s.mailboxes.GetByID(r.Context(), mailboxID)
	if err != nil || mailbox == nil {
		return "", "", fmt.Errorf("mailbox not found")
	}

	if !s.canAccessDomain(r.Context(), mailbox.DomainID) {
		return "", "", fmt.Errorf("access denied")
	}

	domain, err := s.domains.GetByID(r.Context(), mailbox.DomainID)
	if err != nil || domain == nil {
		return "", "", fmt.Errorf("domain not found")
	}

	// Use Dovecot master user for admin access to ManageSieve.
	// Format: user@domain*vectis-admin with internal service token as password.
	userEmail := mailbox.LocalPart + "@" + domain.Name
	masterUser := userEmail + "*vectis-admin"

	return masterUser, s.internalToken, nil
}
