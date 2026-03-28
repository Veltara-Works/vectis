package api

import (
	"fmt"
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/dkim"
	"github.com/Veltara-Works/vectis/internal/repository"
)

var validDomainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)

type createDomainRequest struct {
	Name          string   `json:"name"`
	SpamThreshold *float64 `json:"spam_threshold,omitempty"`
	MaxMailboxes  *int     `json:"max_mailboxes,omitempty"`
}

type updateDomainRequest struct {
	Active        *bool    `json:"active,omitempty"`
	DKIMEnabled   *bool    `json:"dkim_enabled,omitempty"`
	DKIMSelector  *string  `json:"dkim_selector,omitempty"`
	SpamThreshold *float64 `json:"spam_threshold,omitempty"`
	MaxMailboxes  *int     `json:"max_mailboxes,omitempty"`
}

func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	var activeFilter *bool
	if v := r.URL.Query().Get("active"); v == "true" {
		t := true
		activeFilter = &t
	} else if v == "false" {
		f := false
		activeFilter = &f
	}

	domains, err := s.domains.List(r.Context(), activeFilter)
	if err != nil {
		s.logger.Error("list domains failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list domains")
		return
	}
	respond(w, r, http.StatusOK, domains)
}

func (s *Server) handleCreateDomain(w http.ResponseWriter, r *http.Request) {
	var req createDomainRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if req.Name == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "Domain name is required")
		return
	}
	if !validDomainRe.MatchString(req.Name) {
		respondError(w, r, http.StatusBadRequest, "INVALID_DOMAIN", "Invalid domain name format")
		return
	}

	// Check uniqueness.
	existing, _ := s.domains.GetByName(r.Context(), req.Name)
	if existing != nil {
		respondError(w, r, http.StatusConflict, "DOMAIN_EXISTS",
			fmt.Sprintf("Domain %s already exists", req.Name))
		return
	}

	domain, err := s.domains.Create(r.Context(), repository.DomainCreate{
		Name:          req.Name,
		SpamThreshold: req.SpamThreshold,
		MaxMailboxes:  req.MaxMailboxes,
	})
	if err != nil {
		s.logger.Error("create domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create domain")
		return
	}

	// Auto-generate DKIM key pair (Spec A.3: domain creation triggers DKIM generation).
	var dkimInfo *dkimResponse
	if s.dkimBasePath != "" {
		selector := dkim.DefaultSelector()
		kp, err := dkim.GenerateKey(s.dkimBasePath, domain.Name, selector)
		if err != nil {
			s.logger.Warn("DKIM key generation failed", "error", err, "domain", domain.Name)
		} else {
			keyPath := kp.KeyPath
			s.domains.Update(r.Context(), domain.ID, repository.DomainUpdate{
				DKIMSelector: &selector,
				DKIMKeyPath:  &keyPath,
			})
			dkimInfo = &dkimResponse{
				DNSName:  kp.DNSName(),
				DNSValue: kp.DNSRecord(),
				Selector: selector,
				KeyPath:  kp.KeyPath,
			}
			// Refresh domain to include DKIM fields.
			domain, _ = s.domains.GetByID(r.Context(), domain.ID)
		}
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "domain.create", "domain", &domain.ID,
		map[string]string{"name": domain.Name}, &ip)

	type createDomainResponse struct {
		Domain *repository.Domain `json:"domain"`
		DKIM   *dkimResponse      `json:"dkim,omitempty"`
		DNS    *dnsHints          `json:"dns,omitempty"`
	}

	resp := createDomainResponse{Domain: domain, DKIM: dkimInfo}
	if dkimInfo != nil {
		resp.DNS = &dnsHints{
			SPF:   dkim.SPFRecord(""),
			DMARC: dkim.DMARCRecord(domain.Name),
		}
	}

	respond(w, r, http.StatusCreated, resp)
}

type dnsHints struct {
	SPF   string `json:"spf"`
	DMARC string `json:"dmarc"`
}

func (s *Server) handleGetDomain(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")
	domain, err := s.domains.GetByID(r.Context(), domainID)
	if err != nil {
		s.logger.Error("get domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}
	respond(w, r, http.StatusOK, domain)
}

func (s *Server) handleUpdateDomain(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")

	var req updateDomainRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	domain, err := s.domains.Update(r.Context(), domainID, repository.DomainUpdate{
		Active:        req.Active,
		DKIMEnabled:   req.DKIMEnabled,
		DKIMSelector:  req.DKIMSelector,
		SpamThreshold: req.SpamThreshold,
		MaxMailboxes:  req.MaxMailboxes,
	})
	if err != nil {
		s.logger.Error("update domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "domain.update", "domain", &domainID, req, &ip)

	respond(w, r, http.StatusOK, domain)
}

func (s *Server) handleDeleteDomain(w http.ResponseWriter, r *http.Request) {
	domainID := chi.URLParam(r, "domainID")

	// Check for existing mailboxes (Spec A: 409 if mailboxes exist).
	mailboxCount, err := s.domains.CountMailboxes(r.Context(), domainID)
	if err != nil {
		s.logger.Error("count mailboxes failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check mailboxes")
		return
	}
	if mailboxCount > 0 {
		respondErrorWithDetails(w, r, http.StatusConflict, "DOMAIN_HAS_MAILBOXES",
			"Cannot delete domain with existing mailboxes",
			map[string]int{"mailbox_count": mailboxCount})
		return
	}

	// Check for existing aliases.
	aliasCount, err := s.domains.CountAliases(r.Context(), domainID)
	if err != nil {
		s.logger.Error("count aliases failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check aliases")
		return
	}
	if aliasCount > 0 {
		respondErrorWithDetails(w, r, http.StatusConflict, "DOMAIN_HAS_ALIASES",
			"Cannot delete domain with existing aliases",
			map[string]int{"alias_count": aliasCount})
		return
	}

	deleted, err := s.domains.Delete(r.Context(), domainID)
	if err != nil {
		s.logger.Error("delete domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete domain")
		return
	}
	if !deleted {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Domain not found")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "domain.delete", "domain", &domainID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Domain deleted"})
}
