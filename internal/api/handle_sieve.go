package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

const (
	// sieveTokenTTL bounds a single ManageSieve admin operation. It is a backstop
	// only — every caller revokes its token as soon as the operation completes —
	// but keeps a leaked row (handler panic, lost revoke) short-lived. PruneExpired
	// is the final safety net.
	sieveTokenTTL = 2 * time.Minute
	// sievePurpose tags auth tokens minted for ManageSieve admin access, distinct
	// from the importer's "import" and impersonation's "impersonate" tokens so
	// purpose-scoped revokes never clobber each other.
	sievePurpose = "sieve"
)

type sieveScriptRequest struct {
	Name    string `json:"name"`
	Content string `json:"content"`
	Active  bool   `json:"active,omitempty"`
}

// handleListSieveScripts returns all Sieve filter scripts for a mailbox.
func (s *Server) handleListSieveScripts(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	user, pass, revoke, err := s.getMailboxCredentials(r, mailboxID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	defer revoke()

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
	user, pass, revoke, err := s.getMailboxCredentials(r, mailboxID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	defer revoke()

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

	user, pass, revoke, err := s.getMailboxCredentials(r, mailboxID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	defer revoke()

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
	user, pass, revoke, err := s.getMailboxCredentials(r, mailboxID)
	if err != nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}
	defer revoke()

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

// getMailboxCredentials resolves a mailbox ID to a (login, password) pair for
// ManageSieve admin access, plus a revoke func the caller must defer.
//
// It mints a short-lived Dovecot auth token scoped to the mailbox — the same
// proven token-passdb mechanism the native IMAP importer (#112) and admin
// impersonation (#114) use — and returns the mailbox's own address as the login.
// The auth_token passdb is consulted (globally, so ManageSieve-login too) before
// the real mailbox passdb and is fail-safe: a miss/expiry/DB error falls through
// to normal auth. This replaces the unwired `user@domain*vectis-admin` master
// user, which the deployed Dovecot 2.4 stack never actually authenticated.
//
// revoke is always non-nil on success and deletes the token; callers defer it so
// the token lives only for the single ManageSieve operation (TTL is a backstop).
func (s *Server) getMailboxCredentials(r *http.Request, mailboxID string) (login, password string, revoke func(), err error) {
	mailbox, err := s.mailboxes.GetByID(r.Context(), mailboxID)
	if err != nil || mailbox == nil {
		return "", "", nil, fmt.Errorf("mailbox not found")
	}

	if !s.canAccessDomain(r.Context(), mailbox.DomainID) {
		return "", "", nil, fmt.Errorf("access denied")
	}

	domain, err := s.domains.GetByID(r.Context(), mailbox.DomainID)
	if err != nil || domain == nil {
		return "", "", nil, fmt.Errorf("domain not found")
	}

	userEmail := mailbox.LocalPart + "@" + domain.Name
	token, err := s.dovecotTokens.Mint(r.Context(), userEmail, sievePurpose, sieveTokenTTL)
	if err != nil {
		s.logger.Error("mint sieve auth token failed", "error", err, "mailbox_id", mailboxID)
		return "", "", nil, fmt.Errorf("failed to generate credentials")
	}

	revoke = func() {
		// WithoutCancel: revoke even if the request context is already done.
		if rerr := s.dovecotTokens.Revoke(context.WithoutCancel(r.Context()), token.ID); rerr != nil {
			s.logger.Error("revoke sieve auth token failed", "error", rerr, "token_id", token.ID)
		}
	}

	return userEmail, token.Password, revoke, nil
}
