package api

import (
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
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
	Kind    string `json:"kind"`              // 'allow' | 'block' | 'dmarc_exception'
	Scope   string `json:"scope"`             // 'email' | 'domain' (dmarc_exception: 'domain')
	Pattern string `json:"pattern"`           // exact-match value; lowercased on insert
	Network string `json:"network,omitempty"` // dmarc_exception only: IP, CIDR, hostname or .suffix
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
	network := strings.TrimSpace(req.Network)

	switch kind {
	case repository.SpamListAllow, repository.SpamListBlock:
		if network != "" {
			respondError(w, r, http.StatusBadRequest, "INVALID_NETWORK",
				"network applies only to kind 'dmarc_exception'")
			return
		}
	case repository.SpamListDMARCException:
		// A DMARC exception names the header-From domain it lets through,
		// and must be tied to where that mail comes from (#265): an
		// exception for a domain alone would let anyone forge it.
		if scope == "" {
			scope = "domain"
		}
		if scope != "domain" {
			respondError(w, r, http.StatusBadRequest, "INVALID_SCOPE",
				"a DMARC exception's scope is 'domain' (the header From domain)")
			return
		}
		if network == "" {
			respondError(w, r, http.StatusBadRequest, "MISSING_NETWORK",
				"a DMARC exception needs the network the sender's mail comes from: an IP, a CIDR, or a hostname")
			return
		}
		n, code, msg := normalizeExceptionNetwork(network)
		if code != "" {
			respondError(w, r, http.StatusBadRequest, code, msg)
			return
		}
		network = n
	default:
		respondError(w, r, http.StatusBadRequest, "INVALID_KIND",
			"kind must be 'allow', 'block' or 'dmarc_exception'")
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
		Network:  network,
	})
	if err != nil {
		// Duplicate hits the UNIQUE (domain, kind, scope, pattern) constraint.
		// pgx returns a *pgconn.PgError with SQLSTATE 23505; we surface that
		// as a 409 without a strict type assertion to avoid pulling pgconn
		// into the handler — the substring check is good enough here, every
		// other insert failure path is a 500.
		if strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "duplicate key") {
			respondError(w, r, http.StatusConflict, "ENTRY_EXISTS",
				"An entry with this kind+scope+pattern (and network) already exists for this domain")
			return
		}
		s.logger.Error("create spam list entry failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create spam list entry")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	details := map[string]string{"kind": kind, "scope": scope, "pattern": pattern}
	if network != "" {
		details["network"] = network
	}
	s.audit.Log(r.Context(), &adminID, "spam_list.create", "domain", &domain.ID, details, &ip)

	if s.cfg != nil && s.secrets != nil && s.genDir != "" {
		s.regenerateRspamdSpamConfig()
	}

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
		if k != repository.SpamListAllow && k != repository.SpamListBlock && k != repository.SpamListDMARCException {
			respondError(w, r, http.StatusBadRequest, "INVALID_KIND",
				"kind filter must be 'allow', 'block' or 'dmarc_exception'")
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

	deleted, err := s.spamLists.Delete(r.Context(), entryID, s.getAllowedDomainIDs(r.Context()))
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
	delDetails := map[string]string{"entry_id": entryID, "kind": entry.Kind, "scope": entry.Scope, "pattern": entry.Pattern}
	if entry.Network != nil {
		delDetails["network"] = *entry.Network
	}
	s.audit.Log(r.Context(), &adminID, "spam_list.delete", "domain", &domainID, delDetails, &ip)

	if s.cfg != nil && s.secrets != nil && s.genDir != "" {
		s.regenerateRspamdSpamConfig()
	}

	respond(w, r, http.StatusOK, map[string]string{"message": "Spam list entry deleted"})
}

// validSpamLocalPartRe constrains the local part of an email-scope spam pattern
// to the practical address charset. This is a security control, not just a
// validity check: spam patterns are written verbatim into rspamd multimap files
// as "domain:pattern", one per line, so an unvalidated local part containing a
// newline (or the ':' field separator) would inject arbitrary allow/block map
// entries. The host side is already constrained by validDomainRe (audit #118/168).
var validSpamLocalPartRe = regexp.MustCompile(`^[a-z0-9._%+\-]+$`)

// isValidSpamPattern checks scope-specific pattern shape. scope is assumed
// already lowercased and limited to {email, domain}.
func isValidSpamPattern(scope, pattern string) bool {
	switch scope {
	case "email":
		// Exactly one '@', valid local part, valid domain on the right.
		at := strings.Index(pattern, "@")
		if at <= 0 || at != strings.LastIndex(pattern, "@") {
			return false
		}
		local := pattern[:at]
		host := pattern[at+1:]
		if !validSpamLocalPartRe.MatchString(local) || host == "" {
			return false
		}
		return validDomainRe.MatchString(host)
	case "domain":
		return validDomainRe.MatchString(pattern)
	}
	return false
}

// Narrowest-allowed CIDR prefixes for a DMARC exception network. Anything
// wider would exempt a whole provider's address space.
const (
	minExceptionPrefixV4 = 24
	minExceptionPrefixV6 = 48
)

// normalizeExceptionNetwork validates a DMARC exception network and returns
// its canonical form, or an error code and message. Accepted:
//   - an IP address ("27.111.95.31", "2001:db8::25")
//   - a CIDR no wider than /24 (IPv4) or /48 (IPv6), stored masked
//   - a hostname ("mail.example.net"), or a suffix (".mail.example.net"),
//     matched against the forward-confirmed client name Postfix passes on
//
// The result is written verbatim into an rspamd map line, so it must never
// contain whitespace or a separator: every accepted form is canonicalised
// (netip) or charset-constrained (validDomainRe).
func normalizeExceptionNetwork(network string) (string, string, string) {
	n := strings.ToLower(strings.TrimSpace(network))
	if strings.Contains(n, "/") {
		p, err := netip.ParsePrefix(n)
		if err != nil {
			return "", "INVALID_NETWORK", "network is not a valid CIDR"
		}
		min := minExceptionPrefixV4
		if p.Addr().Is6() && !p.Addr().Is4In6() {
			min = minExceptionPrefixV6
		}
		if p.Bits() < min {
			return "", "NETWORK_TOO_BROAD", fmt.Sprintf("a DMARC exception network may be at most /%d for IPv4 or /%d for IPv6", minExceptionPrefixV4, minExceptionPrefixV6)
		}
		return p.Masked().String(), "", ""
	}
	if a, err := netip.ParseAddr(n); err == nil {
		return a.Unmap().String(), "", ""
	}
	host := strings.TrimPrefix(n, ".")
	if strings.HasPrefix(n, ".") && !strings.Contains(host, ".") {
		return "", "NETWORK_TOO_BROAD", "a hostname suffix needs at least two labels (for example .mail.example.net)"
	}
	if !validDomainRe.MatchString(host) {
		return "", "INVALID_NETWORK", "network must be an IP address, a CIDR, a hostname, or a .suffix"
	}
	return n, "", ""
}
