package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// --- GET /api/v1/abuse/events ---

func (s *Server) handleListAbuseEvents(w http.ResponseWriter, r *http.Request) {
	unresolvedOnly := r.URL.Query().Get("unresolved") == "true"

	// Scope the query at the DB layer (R2 + K4): getAllowedDomainIDs is nil for
	// unrestricted principals (all domains) and a non-nil allow-list otherwise,
	// applied in the WHERE before the LIMIT so a scoped caller isn't truncated
	// by a global top-N.
	allowed := s.getAllowedDomainIDs(r.Context())

	var events []repository.AbuseEvent
	var err error
	if unresolvedOnly {
		events, err = s.abuseEvents.ListUnresolved(r.Context(), 100, allowed)
	} else {
		events, err = s.abuseEvents.ListRecent(r.Context(), 100, allowed)
	}
	if err != nil {
		s.logger.Error("list abuse events failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list abuse events")
		return
	}
	respond(w, r, http.StatusOK, events)
}

// --- POST /api/v1/abuse/events/{eventID}/resolve ---

func (s *Server) handleResolveAbuseEvent(w http.ResponseWriter, r *http.Request) {
	eventID := chi.URLParam(r, "eventID")
	adminID := getAdminID(r.Context())

	// R2: resolve the event's domain and enforce scope before acting — this was
	// a by-id mutation with no ownership check (finding A1: resolve/ack any
	// tenant's abuse events). A domain-bound event must pass canAccessDomain; a
	// system event (nil DomainID) may only be resolved by an unrestricted caller.
	event, err := s.abuseEvents.GetByID(r.Context(), eventID)
	if err != nil {
		s.logger.Error("get abuse event failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get event")
		return
	}
	if event == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Abuse event not found")
		return
	}
	if event.DomainID != nil {
		if !s.canAccessDomain(r.Context(), *event.DomainID) {
			respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this event")
			return
		}
	} else if _, unrestricted := s.domainFilter(r.Context()); !unrestricted {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this event")
		return
	}

	if err := s.abuseEvents.Resolve(r.Context(), eventID, adminID, s.getAllowedDomainIDs(r.Context())); err != nil {
		s.logger.Error("resolve abuse event failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to resolve event")
		return
	}

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "abuse.resolve", "abuse_event", &eventID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Abuse event resolved"})
}

// --- POST /api/v1/abuse/mailboxes/{mailboxID}/suspend ---

func (s *Server) handleSuspendMailbox(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	adminID := getAdminID(r.Context())

	// R2: enforce domain scope on this by-id mutation (was RBAC-only, so a
	// scoped key could flip send_suspended on any tenant's mailbox — a
	// cross-tenant outbound-mail DoS, finding A1).
	if _, ok := s.requireMailboxAccess(w, r, mailboxID); !ok {
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if err := decodeJSON(r, &req); err != nil {
		req.Reason = "Manually suspended by admin"
	}
	if req.Reason == "" {
		req.Reason = "Manually suspended by admin"
	}

	if err := s.abuseEvents.SuspendMailbox(r.Context(), mailboxID, req.Reason); err != nil {
		s.logger.Error("suspend mailbox failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to suspend mailbox")
		return
	}

	action := "suspend"
	s.abuseEvents.LogEvent(r.Context(), nil, &mailboxID, "manual_suspend", "info",
		map[string]string{"reason": req.Reason, "admin_id": adminID}, &action)

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "abuse.suspend", "mailbox", &mailboxID,
		map[string]string{"reason": req.Reason}, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Mailbox sending suspended"})
}

// --- POST /api/v1/abuse/mailboxes/{mailboxID}/unsuspend ---

func (s *Server) handleUnsuspendMailbox(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	adminID := getAdminID(r.Context())

	// R2: enforce domain scope on this by-id mutation (finding A1).
	if _, ok := s.requireMailboxAccess(w, r, mailboxID); !ok {
		return
	}

	if err := s.abuseEvents.UnsuspendMailbox(r.Context(), mailboxID); err != nil {
		s.logger.Error("unsuspend mailbox failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to unsuspend mailbox")
		return
	}

	action := "none"
	s.abuseEvents.LogEvent(r.Context(), nil, &mailboxID, "unsuspend", "info",
		map[string]string{"admin_id": adminID}, &action)

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "abuse.unsuspend", "mailbox", &mailboxID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Mailbox sending unsuspended"})
}
