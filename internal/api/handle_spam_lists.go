package api

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// Pro-tier per-domain allow/block lists. The route subtree is gated via
// validonx.FeatureAdvancedSpam at the chi router level (server.go); these
// handlers therefore assume a Pro caller and only perform input validation
// and persistence. Session 2 of the Advanced Spam build wires the repo
// output into rspamd via regenerated multimap files.

type createSpamListRequest struct {
	Kind    string `json:"kind"`    // 'allow' | 'block'
	Scope   string `json:"scope"`   // 'email' | 'domain'
	Pattern string `json:"pattern"` // exact-match value; lowercased on insert
}

type spamListResponse struct {
	Entry *repository.SpamListEntry `json:"entry"`
}

// handleCreateSpamListEntry adds a new allow/block entry under a domain.
//
// POST /api/v1/domains/{domainID}/spam-lists
//
//	body: {"kind":"block", "scope":"domain", "pattern":"spam.example"}
//
// Validation:
//   - domain must exist (404 otherwise)
//   - kind ∈ {allow, block}
//   - scope ∈ {email, domain}
//   - pattern non-empty after trim+lowercase
//   - scope=email → pattern must contain exactly one '@' with non-empty parts
//   - scope=domain → pattern must match validDomainRe
//
// Returns 201 + the created entry on success. Returns 409 if a row with
// the same (domain, kind, scope, pattern) tuple already exists.
func (s *Server) handleCreateSpamListEntry(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")
	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	var req createSpamListRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	scope := strings.ToLower(strings.TrimSpace(req.Scope))
	pattern := strings.ToLower(strings.TrimSpace(req.Pattern))

	if kind != "allow" && kind != "block" {
		respondError(w, r, http.StatusBadRequest, "INVALID_KIND",
			"kind must be 'allow' or 'block'")
		return
	}
	if scope != "email" && scope != "domain" {
		respondError(w, r, http.StatusBadRequest, "INVALID_SCOPE",
			"scope must be 'email' or 'domain'")
		return
	}
	if pattern == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "pattern is required")
		return
	}
	if !isValidSpamPattern(scope, pattern) {
		respondError(w, r, http.StatusBadRequest, "INVALID_PATTERN",
			"pattern does not match the requested scope (expected "+scope+")")
		return
	}

	entry, err := s.spamLists.Create(r.Context(), repository.SpamListCreate{
		DomainID: domain.ID,
		Kind:     kind,
		Scope:    scope,
		Pattern:  pattern,
	})
	if err != nil {
		// Duplicate hits the UNIQUE (domain, kind, scope, pattern) constraint.
		// pgx returns a *pgconn.PgError with SQLSTATE 23505; we surface that
		// as a 409 without a strict type assertion to avoid pulling pgconn
		// into the handler — the substring check is good enough here, every
		// other insert failure path is a 500.
		if strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "duplicate key") {
			respondError(w, r, http.StatusConflict, "ENTRY_EXISTS",
				"An entry with this kind+scope+pattern already exists for this domain")
			return
		}
		s.logger.Error("create spam list entry failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create spam list entry")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "spam_list.create", "domain", &domain.ID,
		map[string]string{"kind": kind, "scope": scope, "pattern": pattern}, &ip)

	respond(w, r, http.StatusCreated, spamListResponse{Entry: entry})
}

// handleListSpamListEntries returns all allow/block entries for a domain,
// optionally filtered by kind via the ?kind=allow|block query param.
//
// GET /api/v1/domains/{domainID}/spam-lists?kind=block
func (s *Server) handleListSpamListEntries(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")
	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	var kindFilter *string
	if k := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind"))); k != "" {
		if k != "allow" && k != "block" {
			respondError(w, r, http.StatusBadRequest, "INVALID_KIND",
				"kind filter must be 'allow' or 'block'")
			return
		}
		kindFilter = &k
	}

	entries, err := s.spamLists.ListByDomain(r.Context(), domain.ID, kindFilter)
	if err != nil {
		s.logger.Error("list spam list entries failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list spam list entries")
		return
	}
	if entries == nil {
		entries = []repository.SpamListEntry{}
	}
	respond(w, r, http.StatusOK, entries)
}

// handleDeleteSpamListEntry removes a single entry.
//
// DELETE /api/v1/domains/{domainID}/spam-lists/{entryID}
//
// We validate the {entryID} actually belongs to {domainID} before deletion
// to prevent cross-domain entry deletion via URL forgery.
func (s *Server) handleDeleteSpamListEntry(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")
	entryID := chi.URLParam(r, "entryID")

	entry, err := s.spamLists.GetByID(r.Context(), entryID)
	if err != nil {
		s.logger.Error("get spam list entry failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load spam list entry")
		return
	}
	if entry == nil || entry.DomainID != domainID {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Spam list entry not found")
		return
	}

	deleted, err := s.spamLists.Delete(r.Context(), entryID)
	if err != nil {
		s.logger.Error("delete spam list entry failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete spam list entry")
		return
	}
	if !deleted {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Spam list entry not found")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "spam_list.delete", "domain", &domainID,
		map[string]string{"entry_id": entryID, "kind": entry.Kind, "scope": entry.Scope, "pattern": entry.Pattern}, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Spam list entry deleted"})
}

// isValidSpamPattern checks scope-specific pattern shape. scope is assumed
// already lowercased and limited to {email, domain}.
func isValidSpamPattern(scope, pattern string) bool {
	switch scope {
	case "email":
		// Exactly one '@', non-empty local part, valid domain on the right.
		at := strings.Index(pattern, "@")
		if at <= 0 || at != strings.LastIndex(pattern, "@") {
			return false
		}
		local := pattern[:at]
		host := pattern[at+1:]
		if local == "" || host == "" {
			return false
		}
		return validDomainRe.MatchString(host)
	case "domain":
		return validDomainRe.MatchString(pattern)
	}
	return false
}
