package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// createImportRequest starts an import of an external IMAP account INTO the
// path mailbox. The source password is write-only (encrypted at rest, never
// echoed back by any status read).
type createImportRequest struct {
	SourceHost     string `json:"source_host"`
	SourcePort     int    `json:"source_port,omitempty"` // default 993
	SourceTLS      *bool  `json:"source_tls,omitempty"`  // default true (implicit TLS)
	SourceUser     string `json:"source_user"`
	SourcePassword string `json:"source_password"`
}

// --- POST /api/v1/mailboxes/{mailboxID}/import ---

func (s *Server) handleCreateImport(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	mailbox, ok := s.requireMailboxAccess(w, r, mailboxID)
	if !ok {
		return
	}

	var req createImportRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}
	req.SourceHost = strings.TrimSpace(req.SourceHost)
	req.SourceUser = strings.TrimSpace(req.SourceUser)
	if req.SourceHost == "" || req.SourceUser == "" || req.SourcePassword == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS",
			"source_host, source_user and source_password are required")
		return
	}
	tls := true
	if req.SourceTLS != nil {
		tls = *req.SourceTLS
	}

	adminID := getAdminID(r.Context())
	job, err := s.importJobs.Create(r.Context(), repository.ImportCreate{
		MailboxID:      mailbox.ID,
		SourceHost:     req.SourceHost,
		SourcePort:     req.SourcePort,
		SourceTLS:      tls,
		SourceUser:     req.SourceUser,
		SourcePassword: req.SourcePassword,
		TriggeredBy:    &adminID,
	})
	if err != nil {
		s.logger.Error("create import job failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create import job")
		return
	}

	// Hand it to the background worker now; if the worker is somehow absent the
	// recovery scan still picks the pending job up.
	if s.importWorker != nil {
		s.importWorker.Enqueue(job.ID)
	}

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "mailbox.import.create", "imap_import_job", &job.ID,
		map[string]string{"mailbox_id": mailbox.ID, "source_host": req.SourceHost, "source_user": req.SourceUser}, &ip)

	respond(w, r, http.StatusAccepted, job)
}

// --- GET /api/v1/mailboxes/{mailboxID}/imports ---

func (s *Server) handleListImports(w http.ResponseWriter, r *http.Request) {
	mailboxID := chi.URLParam(r, "mailboxID")
	mailbox, ok := s.requireMailboxAccess(w, r, mailboxID)
	if !ok {
		return
	}
	jobs, err := s.importJobs.ListByMailbox(r.Context(), mailbox.ID, 20)
	if err != nil {
		s.logger.Error("list import jobs failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list import jobs")
		return
	}
	if jobs == nil {
		jobs = []repository.ImportJob{}
	}
	respond(w, r, http.StatusOK, jobs)
}

// --- GET /api/v1/mailboxes/{mailboxID}/imports/{jobID} ---

func (s *Server) handleGetImport(w http.ResponseWriter, r *http.Request) {
	mailbox, job, ok := s.requireImportJob(w, r)
	if !ok {
		return
	}
	_ = mailbox
	respond(w, r, http.StatusOK, job)
}

// --- POST /api/v1/mailboxes/{mailboxID}/imports/{jobID}/cancel ---

func (s *Server) handleCancelImport(w http.ResponseWriter, r *http.Request) {
	mailbox, job, ok := s.requireImportJob(w, r)
	if !ok {
		return
	}
	cancelled, err := s.importJobs.Cancel(r.Context(), job.ID)
	if err != nil {
		s.logger.Error("cancel import job failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to cancel import job")
		return
	}
	if !cancelled {
		respondError(w, r, http.StatusConflict, "NOT_CANCELLABLE",
			"Import job is already finished and cannot be cancelled")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "mailbox.import.cancel", "imap_import_job", &job.ID,
		map[string]string{"mailbox_id": mailbox.ID}, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Import job cancellation requested"})
}

// requireImportJob resolves and authorises {mailboxID}/{jobID}: the caller must
// have access to the mailbox AND the job must belong to it. Writes the error
// response and returns ok=false on any failure.
func (s *Server) requireImportJob(w http.ResponseWriter, r *http.Request) (*repository.Mailbox, *repository.ImportJob, bool) {
	mailboxID := chi.URLParam(r, "mailboxID")
	mailbox, ok := s.requireMailboxAccess(w, r, mailboxID)
	if !ok {
		return nil, nil, false
	}
	jobID := chi.URLParam(r, "jobID")
	job, err := s.importJobs.GetByID(r.Context(), jobID)
	if errors.Is(err, pgx.ErrNoRows) {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Import job not found")
		return nil, nil, false
	}
	if err != nil {
		s.logger.Error("get import job failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get import job")
		return nil, nil, false
	}
	// Prevent cross-mailbox access via a mismatched path.
	if job.MailboxID != mailbox.ID {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Import job not found")
		return nil, nil, false
	}
	return mailbox, job, true
}
