package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// --- GET /api/v1/abuse/events ---

func (s *Server) handleListAbuseEvents(w http.ResponseWriter, r *http.Request) {
	unresolvedOnly := r.URL.Query().Get("unresolved") == "true"

	var events interface{}
	var err error
	if unresolvedOnly {
		events, err = s.abuseEvents.ListUnresolved(r.Context(), 100)
	} else {
		events, err = s.abuseEvents.ListRecent(r.Context(), 100)
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

	if err := s.abuseEvents.Resolve(r.Context(), eventID, adminID); err != nil {
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
