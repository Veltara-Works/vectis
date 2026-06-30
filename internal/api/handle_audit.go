package api

import (
	"net/http"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// --- GET /api/v1/audit ---

func (s *Server) handleListAudit(w http.ResponseWriter, r *http.Request) {
	page, err := parsePagination(r)
	if err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_PAGINATION", err.Error())
		return
	}

	action := r.URL.Query().Get("action")
	resourceType := r.URL.Query().Get("resource_type")
	adminID := r.URL.Query().Get("admin_id")

	entries, err := s.audit.ListPaginated(r.Context(), action, resourceType, adminID, repository.PaginationParams{
		Cursor: page.Cursor,
		Limit:  page.Limit,
	})
	if err != nil {
		s.logger.Error("list audit failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list audit log")
		return
	}

	respondPaginatedSlice(w, r, http.StatusOK, entries, page.Limit, func(e repository.AuditEntry) time.Time { return e.CreatedAt })
}
