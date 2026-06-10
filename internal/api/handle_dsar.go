package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/dsar"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// dsarService builds a DSAR service from the server's repos. Cheap (a bag of
// pointers), so we construct one per request rather than holding a field. The
// Maildir root is derived from the Dovecot mail_location; the api container
// mounts mail-data RW at that path, so full message bodies are read directly.
func (s *Server) dsarService() *dsar.Service {
	mailLoc := ""
	if s.cfg != nil {
		mailLoc = s.cfg.Dovecot.MailLocation
	}
	return dsar.NewService(
		s.domains, s.mailboxes, s.aliases, s.admins, s.messages,
		s.audit, s.erasureTombstones,
		dsar.MailRootFromLocation(mailLoc),
		s.logger.With("component", "dsar"),
	)
}

// handleDSARExport streams a GDPR Art.15 access package (zip) for a data
// subject. Super-admin + Enterprise (dsar) gated at the route.
// Query: subject=<email> (required).
func (s *Server) handleDSARExport(w http.ResponseWriter, r *http.Request) {
	subject := strings.TrimSpace(r.URL.Query().Get("subject"))
	if subject == "" {
		respondError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "subject (email) is required")
		return
	}

	svc := s.dsarService()

	// Pre-check existence before writing any download headers, so a missing
	// subject returns a clean 404 instead of a half-streamed zip.
	exists, err := svc.SubjectHasMailbox(r.Context(), subject)
	if err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_REQUEST", err.Error())
		return
	}
	if !exists {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "No mailbox found for that subject")
		return
	}

	adminID := getAdminID(r.Context())
	filename := dsar.ExportFilename(subject, time.Now())
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=\""+filename+"\"")

	if _, err := svc.Export(r.Context(), subject, &adminID, w); err != nil {
		// Headers (200) are already committed once streaming starts; we can only
		// log. The truncated zip is the client's signal that the export failed.
		s.logger.Error("dsar export failed mid-stream", "subject", subject, "error", err)
		return
	}
}

// dsarEraseRequest is the body for an erasure request.
type dsarEraseRequest struct {
	Subject string `json:"subject"`
	Confirm bool   `json:"confirm"`
}

// handleDSARErase hard-deletes a data subject's live personal data (GDPR
// Art.17) and records a restore-surviving tombstone. Super-admin + Enterprise
// (dsar) gated at the route. Body: {"subject":"<email>","confirm":true}.
func (s *Server) handleDSARErase(w http.ResponseWriter, r *http.Request) {
	var req dsarEraseRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "Invalid JSON body")
		return
	}
	req.Subject = strings.TrimSpace(req.Subject)
	if req.Subject == "" {
		respondError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "subject (email) is required")
		return
	}
	if !req.Confirm {
		respondError(w, r, http.StatusBadRequest, "CONFIRMATION_REQUIRED",
			"Erasure is irreversible. Set \"confirm\": true to proceed.")
		return
	}

	adminID := getAdminID(r.Context())
	res, err := s.dsarService().Erase(r.Context(), req.Subject, &adminID)
	if err != nil {
		if errors.Is(err, dsar.ErrSubjectNotFound) {
			respondError(w, r, http.StatusNotFound, "NOT_FOUND", "No mailbox found for that subject")
			return
		}
		s.logger.Error("dsar erase failed", "subject", req.Subject, "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to erase subject")
		return
	}
	respond(w, r, http.StatusOK, res)
}

// handleDSARListErasures returns the erasure tombstones (the suppression list).
// Super-admin + Enterprise (dsar) gated at the route.
func (s *Server) handleDSARListErasures(w http.ResponseWriter, r *http.Request) {
	tombs, err := s.erasureTombstones.List(r.Context())
	if err != nil {
		s.logger.Error("dsar list erasures failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list erasures")
		return
	}
	if tombs == nil {
		tombs = []repository.ErasureTombstone{}
	}
	respond(w, r, http.StatusOK, map[string]any{"erasures": tombs, "count": len(tombs)})
}

// ReconcileErasureTombstones re-applies every recorded erasure against current
// live data. Called once on startup so an erasure survives a backup restore
// (the restored server re-purges any resurrected subject on boot). Runs in the
// background with its own timeout; failures are logged, never fatal.
func (s *Server) ReconcileErasureTombstones() {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		if _, err := s.dsarService().ReconcileTombstones(ctx); err != nil {
			s.logger.Error("dsar: tombstone reconcile on startup failed", "error", err)
		}
	}()
}
