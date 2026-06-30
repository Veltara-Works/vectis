package api

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/repository"
)

type createAliasRequest struct {
	DomainID        string `json:"domain_id"`
	SourceLocalPart string `json:"source_local_part"`
	Destination     string `json:"destination"`
}

type updateAliasRequest struct {
	Destination *string `json:"destination,omitempty"`
	Active      *bool   `json:"active,omitempty"`
}

func (s *Server) handleListAliases(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")
	if domainID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "domain_id query parameter is required")
		return
	}
	if !s.canAccessDomain(r.Context(), domainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
		return
	}

	page, err := parsePagination(r)
	if err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_PAGINATION", err.Error())
		return
	}

	aliases, err := s.aliases.ListByDomainPaginated(r.Context(), domainID, repository.PaginationParams{
		Cursor: page.Cursor,
		Limit:  page.Limit,
	})
	if err != nil {
		s.logger.Error("list aliases failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list aliases")
		return
	}

	respondPaginatedSlice(w, r, http.StatusOK, aliases, page.Limit, func(a repository.Alias) time.Time { return a.CreatedAt })
}

func (s *Server) handleCreateAlias(w http.ResponseWriter, r *http.Request) {
	var req createAliasRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if req.DomainID == "" || req.Destination == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "domain_id and destination are required")
		return
	}
	if !s.canAccessDomain(r.Context(), req.DomainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
		return
	}

	// source_local_part can be empty string (catch-all), so we don't validate it as required.

	// Check domain exists.
	domain, err := s.domains.GetByID(r.Context(), req.DomainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to verify domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusBadRequest, "DOMAIN_NOT_FOUND", "Domain does not exist")
		return
	}

	// Check uniqueness.
	existing, _ := s.aliases.GetBySource(r.Context(), req.DomainID, req.SourceLocalPart)
	if existing != nil {
		source := req.SourceLocalPart
		if source == "" {
			source = "(catch-all)"
		}
		respondError(w, r, http.StatusConflict, "ALIAS_EXISTS",
			fmt.Sprintf("Alias %s@%s already exists", source, domain.Name))
		return
	}

	// Validate no alias chaining (Spec B.4): destination must not point to another alias.
	for _, dest := range strings.Split(req.Destination, ",") {
		dest = strings.TrimSpace(dest)
		parts := strings.SplitN(dest, "@", 2)
		if len(parts) == 2 {
			destDomain, err := s.domains.GetByName(r.Context(), parts[1])
			if err == nil && destDomain != nil {
				existingAlias, _ := s.aliases.GetBySource(r.Context(), destDomain.ID, parts[0])
				if existingAlias != nil {
					respondError(w, r, http.StatusBadRequest, "ALIAS_CHAINING",
						fmt.Sprintf("Destination %s is itself an alias; alias chaining is not allowed", dest))
					return
				}
			}
		}
	}

	alias, err := s.aliases.Create(r.Context(), repository.AliasCreate{
		DomainID:        req.DomainID,
		SourceLocalPart: req.SourceLocalPart,
		Destination:     req.Destination,
	})
	if err != nil {
		s.logger.Error("create alias failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create alias")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "alias.create", "alias", &alias.ID,
		map[string]string{"source": req.SourceLocalPart, "destination": req.Destination, "domain": domain.Name}, &ip)

	respond(w, r, http.StatusCreated, alias)
}

// requireAliasAccess fetches the alias by ID and verifies the caller may access
// its domain. On any failure it writes the error response and returns ok=false.
// Guards the by-ID handlers against cross-domain IDOR (audit P3-M2).
func (s *Server) requireAliasAccess(w http.ResponseWriter, r *http.Request, aliasID string) (*repository.Alias, bool) {
	alias, err := s.aliases.GetByID(r.Context(), aliasID)
	if err != nil {
		s.logger.Error("get alias failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get alias")
		return nil, false
	}
	if alias == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Alias not found")
		return nil, false
	}
	if !s.canAccessDomain(r.Context(), alias.DomainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this alias")
		return nil, false
	}
	return alias, true
}

func (s *Server) handleGetAlias(w http.ResponseWriter, r *http.Request) {
	aliasID := chi.URLParam(r, "aliasID")
	alias, ok := s.requireAliasAccess(w, r, aliasID)
	if !ok {
		return
	}
	respond(w, r, http.StatusOK, alias)
}

func (s *Server) handleUpdateAlias(w http.ResponseWriter, r *http.Request) {
	aliasID := chi.URLParam(r, "aliasID")

	if _, ok := s.requireAliasAccess(w, r, aliasID); !ok {
		return
	}

	var req updateAliasRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	alias, err := s.aliases.Update(r.Context(), aliasID, repository.AliasUpdate{
		Destination: req.Destination,
		Active:      req.Active,
	})
	if err != nil {
		s.logger.Error("update alias failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update alias")
		return
	}
	if alias == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Alias not found")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "alias.update", "alias", &aliasID, req, &ip)

	respond(w, r, http.StatusOK, alias)
}

func (s *Server) handleDeleteAlias(w http.ResponseWriter, r *http.Request) {
	aliasID := chi.URLParam(r, "aliasID")

	if _, ok := s.requireAliasAccess(w, r, aliasID); !ok {
		return
	}

	deleted, err := s.aliases.Delete(r.Context(), aliasID)
	if err != nil {
		s.logger.Error("delete alias failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete alias")
		return
	}
	if !deleted {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Alias not found")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "alias.delete", "alias", &aliasID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Alias deleted"})
}
