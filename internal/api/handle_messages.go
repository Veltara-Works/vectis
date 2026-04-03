package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// handleListMessages returns paginated message metadata with filtering.
// Query params: domain_id, direction (inbound/outbound), status, search, sender
func (s *Server) handleListMessages(w http.ResponseWriter, r *http.Request) {
	pg, err := parsePagination(r)
	if err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_PAGINATION", err.Error())
		return
	}

	filter := repository.MessageFilter{
		DomainID:  r.URL.Query().Get("domain_id"),
		Direction: r.URL.Query().Get("direction"),
		Status:    r.URL.Query().Get("status"),
		Search:    r.URL.Query().Get("search"),
		Sender:    r.URL.Query().Get("sender"),
	}

	// Domain access check for domain_admin.
	if filter.DomainID != "" && !s.canAccessDomain(r.Context(), filter.DomainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
		return
	}

	// For domain_admin with no explicit filter, scope to their domains.
	if filter.DomainID == "" {
		allowedIDs := s.getAllowedDomainIDs(r.Context())
		if allowedIDs != nil && len(allowedIDs) == 0 {
			respond(w, r, http.StatusOK, []any{})
			return
		}
		// If allowedIDs is non-nil (domain_admin), we need per-domain filtering.
		// For simplicity, require domain_id for domain_admin.
		if allowedIDs != nil {
			respondError(w, r, http.StatusBadRequest, "DOMAIN_REQUIRED",
				"domain_id query parameter is required for domain-scoped admins")
			return
		}
	}

	repoPg := repository.PaginationParams{
		Cursor: pg.Cursor,
		Limit:  pg.Limit,
	}

	messages, err := s.messages.List(r.Context(), filter, repoPg)
	if err != nil {
		s.logger.Error("list messages failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list messages")
		return
	}

	hasMore := len(messages) > pg.Limit
	if hasMore {
		messages = messages[:pg.Limit]
	}

	nextCursor := ""
	if hasMore && len(messages) > 0 {
		nextCursor = encodeCursor(messages[len(messages)-1].CreatedAt)
	}

	respondPaginated(w, r, http.StatusOK, messages, nextCursor, hasMore)
}

// handleGetMessage retrieves a single message by ID.
func (s *Server) handleGetMessage(w http.ResponseWriter, r *http.Request) {
	messageID := chi.URLParam(r, "messageID")
	if messageID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_ID", "Message ID is required")
		return
	}

	msg, err := s.messages.GetByID(r.Context(), messageID)
	if err != nil {
		s.logger.Error("get message failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get message")
		return
	}
	if msg == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Message not found")
		return
	}

	if !s.canAccessDomain(r.Context(), msg.DomainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this message")
		return
	}

	respond(w, r, http.StatusOK, msg)
}
