package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/dkim"
	"github.com/Veltara-Works/vectis/internal/engine"
	"github.com/Veltara-Works/vectis/internal/validonx"
	"github.com/Veltara-Works/vectis/internal/repository"
)

var validDomainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$`)

type createDomainRequest struct {
	Name            string   `json:"name"`
	SpamThreshold   *float64 `json:"spam_threshold,omitempty"`
	RejectThreshold *float64 `json:"reject_threshold,omitempty"`
	GreylistEnabled *bool    `json:"greylist_enabled,omitempty"`
	MaxMailboxes    *int     `json:"max_mailboxes,omitempty"`
}

type updateDomainRequest struct {
	Active          *bool    `json:"active,omitempty"`
	DKIMEnabled     *bool    `json:"dkim_enabled,omitempty"`
	DKIMSelector    *string  `json:"dkim_selector,omitempty"`
	SpamThreshold   *float64 `json:"spam_threshold,omitempty"`
	RejectThreshold *float64 `json:"reject_threshold,omitempty"`
	GreylistEnabled *bool    `json:"greylist_enabled,omitempty"`
	MaxMailboxes    *int     `json:"max_mailboxes,omitempty"`
}

// usesAdvancedSpamFields reports whether the request payload touches any
// Pro-gated per-domain spam knobs. Used for the field-level FeatureGate
// check in create/update handlers — if any of these are non-nil we must
// reject the whole request on Free tier (decision D2 in plan
// proceed-with-advanced-spam-splendid-creek). spam_threshold is NOT in this
// set: it has been free + ungated since v0.1.0 and stays that way.
func (req *createDomainRequest) usesAdvancedSpamFields() bool {
	return req.RejectThreshold != nil || req.GreylistEnabled != nil
}

func (req *updateDomainRequest) usesAdvancedSpamFields() bool {
	return req.RejectThreshold != nil || req.GreylistEnabled != nil
}

func (s *Server) handleListDomains(w http.ResponseWriter, r *http.Request) {
	// domain_admin: return only assigned domains (no pagination, small set).
	if getAdminRole(r.Context()) == auth.RoleDomainAdmin {
		allowedIDs := s.getAllowedDomainIDs(r.Context())
		domains, err := s.domains.ListByIDs(r.Context(), allowedIDs)
		if err != nil {
			s.logger.Error("list domains for domain_admin failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list domains")
			return
		}
		respondPaginated(w, r, http.StatusOK, domains, "", false)
		return
	}

	var activeFilter *bool
	if v := r.URL.Query().Get("active"); v == "true" {
		t := true
		activeFilter = &t
	} else if v == "false" {
		f := false
		activeFilter = &f
	}

	page, err := parsePagination(r)
	if err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_PAGINATION", err.Error())
		return
	}

	domains, err := s.domains.ListPaginated(r.Context(), activeFilter, repository.PaginationParams{
		Cursor: page.Cursor,
		Limit:  page.Limit,
	})
	if err != nil {
		s.logger.Error("list domains failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list domains")
		return
	}

	hasMore := len(domains) > page.Limit
	var nextCursor string
	if hasMore {
		domains = domains[:page.Limit]
		nextCursor = encodeCursor(domains[page.Limit-1].CreatedAt)
	}

	respondPaginated(w, r, http.StatusOK, domains, nextCursor, hasMore)
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

	// Free-tier resource cap: 3 domains max, 25 mailboxes per domain default.
	// Per pricing.astro Starter promise. Pro/Enterprise are uncapped here.
	// Existing domains on a customer who downgrades Pro→Free are NOT
	// retroactively deleted; this only blocks NEW domain creation past 3.
	tier, _ := s.featureGate.ResolveTier(r.Context())
	if tier == validonx.TierFree && req.usesAdvancedSpamFields() {
		respondError(w, r, http.StatusForbidden, "FEATURE_NOT_AVAILABLE",
			"reject_threshold and greylist_enabled require a Pro license (advanced_spam)")
		return
	}
	maxMailboxes := req.MaxMailboxes
	if tier == validonx.TierFree {
		count, countErr := s.domains.Count(r.Context(), nil)
		if countErr != nil {
			s.logger.Error("count domains failed", "error", countErr)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to verify domain quota")
			return
		}
		if count >= 3 {
			respondError(w, r, http.StatusForbidden, "LIMIT_EXCEEDED",
				"Starter plan allows up to 3 domains. Upgrade to Pro for unlimited domains.")
			return
		}
		// Default mailbox cap to 25 for Free if caller didn't specify a tighter limit.
		if maxMailboxes == nil {
			defaultCap := 25
			maxMailboxes = &defaultCap
		}
	}

	domain, err := s.domains.Create(r.Context(), repository.DomainCreate{
		Name:            req.Name,
		SpamThreshold:   req.SpamThreshold,
		RejectThreshold: req.RejectThreshold,
		GreylistEnabled: req.GreylistEnabled,
		MaxMailboxes:    maxMailboxes,
	})
	if err != nil {
		s.logger.Error("create domain failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create domain")
		return
	}

	// Pre-create the domain's maildir root with vmail ownership (uid/gid
	// 5000). If we don't, the first process to touch the path (Dovecot LMTP
	// auto-create, Postfix virtual delivery, a manual debug command) might
	// create it with the wrong uid — we've seen domains land at uid 101,
	// breaking delivery with "permission denied / missing +x" because
	// Dovecot runs as uid 5000. This is the defensive half of the fix; the
	// other half is getting the postfix container's vmail user to uid 5000.
	domainMaildir := filepath.Join("/var/vectis/mail", domain.Name)
	if err := os.MkdirAll(domainMaildir, 0700); err != nil {
		s.logger.Warn("pre-create domain maildir failed", "path", domainMaildir, "error", err)
	}
	if err := os.Chown(domainMaildir, 5000, 5000); err != nil {
		s.logger.Warn("chown domain maildir failed", "path", domainMaildir, "error", err)
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

	// ADR-023: Regenerate Rspamd DKIM signing config and reload Rspamd.
	if s.cfg != nil && s.secrets != nil && s.genDir != "" {
		s.regenerateRspamdDKIMConfig()
		// If the create touched per-domain spam knobs, also rewrite the
		// rspamd settings.conf so the override takes effect immediately
		// without waiting for the next config apply.
		if req.usesAdvancedSpamFields() {
			s.regenerateRspamdSpamConfig()
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
	if !s.canAccessDomain(r.Context(), domainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
		return
	}
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

	// Field-level Pro gate: reject the whole PATCH if a Free-tier caller
	// tries to set reject_threshold or greylist_enabled. spam_threshold
	// remains ungated (existed since v0.1.0). Decision D1+D2 in plan
	// proceed-with-advanced-spam-splendid-creek.
	if req.usesAdvancedSpamFields() {
		tier, _ := s.featureGate.ResolveTier(r.Context())
		if tier == validonx.TierFree {
			respondError(w, r, http.StatusForbidden, "FEATURE_NOT_AVAILABLE",
				"reject_threshold and greylist_enabled require a Pro license (advanced_spam)")
			return
		}
	}

	domain, err := s.domains.Update(r.Context(), domainID, repository.DomainUpdate{
		Active:          req.Active,
		DKIMEnabled:     req.DKIMEnabled,
		DKIMSelector:    req.DKIMSelector,
		SpamThreshold:   req.SpamThreshold,
		RejectThreshold: req.RejectThreshold,
		GreylistEnabled: req.GreylistEnabled,
		MaxMailboxes:    req.MaxMailboxes,
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

	if req.usesAdvancedSpamFields() && s.cfg != nil && s.secrets != nil && s.genDir != "" {
		s.regenerateRspamdSpamConfig()
	}

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

	// ADR-023: Regenerate Rspamd DKIM config after domain removal.
	// Also rewrite spam-list/settings config so any cascade-deleted spam
	// list rows (FK ON DELETE CASCADE on domain_spam_lists) and the now-
	// gone per-domain settings block stop being referenced.
	if s.cfg != nil && s.secrets != nil && s.genDir != "" {
		s.regenerateRspamdDKIMConfig()
		s.regenerateRspamdSpamConfig()
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "domain.delete", "domain", &domainID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Domain deleted"})
}

// regenerateRspamdDKIMConfig regenerates the Rspamd DKIM signing config from
// the current domain list and triggers an Rspamd reload (ADR-023).
func (s *Server) regenerateRspamdDKIMConfig() {
	ctx := context.Background()
	domains, err := s.domains.List(ctx, nil)
	if err != nil {
		s.logger.Warn("failed to list domains for DKIM config regeneration", "error", err)
		return
	}

	data := engine.NewTemplateData(s.cfg, s.secrets, domains)
	files, err := engine.Generate(data)
	if err != nil {
		s.logger.Warn("failed to generate DKIM config", "error", err)
		return
	}

	// Write only the DKIM signing config file.
	for _, f := range files {
		if f.RelPath == "rspamd/dkim_signing.conf" {
			if err := engine.WriteFiles(s.genDir, []engine.GeneratedFile{f}); err != nil {
				s.logger.Warn("failed to write DKIM signing config", "error", err)
				return
			}
			break
		}
	}

	// Reload Rspamd.
	results := engine.ExecuteActions([]engine.ServiceAction{
		{Service: "rspamd", Action: "reload", Reason: "DKIM config updated"},
	})
	for _, r := range results {
		if !r.Success {
			s.logger.Warn("rspamd reload failed after DKIM config update", "error", r.Error)
		} else {
			s.logger.Info("rspamd reloaded after DKIM config update")
		}
	}
}

// loadSpamListInfos returns every per-domain allow/block entry mapped into
// the engine.SpamListInfo shape. Errors are logged and treated as empty —
// pre-migration installs (no domain_spam_lists table) and Free-tier installs
// with no entries both produce the same empty-list outcome, which is the
// correct rspamd config (no-op prefilter, empty maps).
func (s *Server) loadSpamListInfos(ctx context.Context) []engine.SpamListInfo {
	entries, err := s.spamLists.ListAll(ctx)
	if err != nil {
		s.logger.Warn("failed to load spam list entries (advanced spam config will be empty)", "error", err)
		return nil
	}
	out := make([]engine.SpamListInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, engine.SpamListInfo{
			DomainName: e.DomainName,
			Kind:       e.Kind,
			Scope:      e.Scope,
			Pattern:    e.Pattern,
		})
	}
	return out
}

// regenerateRspamdSpamConfig rewrites the four per-recipient-domain
// allow/block map files, the Lua extension, and the per-domain
// settings.conf, then reloads Rspamd. Called from the spam-list CRUD
// handlers and from domain create/update/delete whenever the request
// touched reject_threshold or greylist_enabled.
//
// The Lua extension and map files are static-shaped — they exist with
// empty content even when no Pro entries are present — so the bind
// mounts in docker-compose are always valid.
func (s *Server) regenerateRspamdSpamConfig() {
	ctx := context.Background()
	domains, err := s.domains.List(ctx, nil)
	if err != nil {
		s.logger.Warn("failed to list domains for spam config regeneration", "error", err)
		return
	}

	entries, err := s.spamLists.ListAll(ctx)
	if err != nil {
		s.logger.Warn("failed to list spam list entries for regeneration", "error", err)
		return
	}

	data := engine.NewTemplateData(s.cfg, s.secrets, domains)
	data.SpamListEntries = make([]engine.SpamListInfo, 0, len(entries))
	for _, e := range entries {
		data.SpamListEntries = append(data.SpamListEntries, engine.SpamListInfo{
			DomainName: e.DomainName,
			Kind:       e.Kind,
			Scope:      e.Scope,
			Pattern:    e.Pattern,
		})
	}

	files, err := engine.Generate(data)
	if err != nil {
		s.logger.Warn("failed to generate spam config", "error", err)
		return
	}

	wanted := map[string]bool{
		"rspamd/settings.conf":         true,
		"rspamd/rspamd.local.lua":      true,
		"rspamd/maps/allow_email.map":  true,
		"rspamd/maps/allow_domain.map": true,
		"rspamd/maps/block_email.map":  true,
		"rspamd/maps/block_domain.map": true,
	}
	subset := make([]engine.GeneratedFile, 0, len(wanted))
	for _, f := range files {
		if wanted[f.RelPath] {
			subset = append(subset, f)
		}
	}
	if err := engine.WriteFiles(s.genDir, subset); err != nil {
		s.logger.Warn("failed to write spam config files", "error", err)
		return
	}

	results := engine.ExecuteActions([]engine.ServiceAction{
		{Service: "rspamd", Action: "reload", Reason: "spam list / per-domain spam config updated"},
	})
	for _, r := range results {
		if !r.Success {
			s.logger.Warn("rspamd reload failed after spam config update", "error", r.Error)
		} else {
			s.logger.Info("rspamd reloaded after spam config update")
		}
	}
}
