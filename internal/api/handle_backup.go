package api

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/backup"
)

// --- POST /api/v1/backup/create ---

func (s *Server) handleBackupCreate(w http.ResponseWriter, r *http.Request) {
	adminID := getAdminID(r.Context())

	mgr := s.backupManager()
	if mgr == nil {
		respondError(w, r, http.StatusServiceUnavailable, "BACKUP_NOT_CONFIGURED",
			"Backup manager is not configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var triggeredBy *string
	if adminID != "" {
		triggeredBy = &adminID
	}

	jobID, err := mgr.CreateAsync(ctx, triggeredBy)
	if err != nil {
		s.logger.Error("backup create failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "BACKUP_ERROR", "Failed to create backup")
		return
	}

	respond(w, r, http.StatusAccepted, map[string]string{
		"job_id":  jobID,
		"message": "Backup job started",
	})
}

// --- GET /api/v1/backup/status/{jobId} ---

func (s *Server) handleBackupStatus(w http.ResponseWriter, r *http.Request) {
	jobID := chi.URLParam(r, "jobId")
	if jobID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_JOB_ID", "Job ID is required")
		return
	}

	mgr := s.backupManager()
	if mgr == nil {
		respondError(w, r, http.StatusServiceUnavailable, "BACKUP_NOT_CONFIGURED",
			"Backup manager is not configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	job, err := mgr.GetJobStatus(ctx, jobID)
	if err != nil {
		s.logger.Error("backup status query failed", "error", err, "job_id", jobID)
		respondError(w, r, http.StatusNotFound, "JOB_NOT_FOUND",
			"Backup job not found")
		return
	}

	respond(w, r, http.StatusOK, job)
}

// --- GET /api/v1/backup/list ---

func (s *Server) handleBackupList(w http.ResponseWriter, r *http.Request) {
	mgr := s.backupManager()
	if mgr == nil {
		respondError(w, r, http.StatusServiceUnavailable, "BACKUP_NOT_CONFIGURED",
			"Backup manager is not configured")
		return
	}

	backups, err := mgr.List()
	if err != nil {
		s.logger.Error("backup list failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "BACKUP_ERROR", "Failed to list backups")
		return
	}

	if backups == nil {
		backups = []backup.BackupInfo{}
	}

	respond(w, r, http.StatusOK, backups)
}

// --- POST /api/v1/backup/restore/{id} ---

func (s *Server) handleBackupRestore(w http.ResponseWriter, r *http.Request) {
	// Require X-Confirm-Restore header for destructive operation.
	if r.Header.Get("X-Confirm-Restore") != "true" {
		respondError(w, r, http.StatusBadRequest, "CONFIRM_REQUIRED",
			"Restore is a destructive operation. Set X-Confirm-Restore: true header to proceed.")
		return
	}

	backupID := chi.URLParam(r, "id")
	if backupID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_BACKUP_ID", "Backup ID is required")
		return
	}

	adminID := getAdminID(r.Context())

	mgr := s.backupManager()
	if mgr == nil {
		respondError(w, r, http.StatusServiceUnavailable, "BACKUP_NOT_CONFIGURED",
			"Backup manager is not configured")
		return
	}

	// Find the backup file. The ID is treated as either a filename or a path.
	// First try to find it in the backup directory by listing available backups.
	backups, err := mgr.List()
	if err != nil {
		s.logger.Error("backup list failed during restore", "error", err)
		respondError(w, r, http.StatusInternalServerError, "BACKUP_ERROR", "Failed to list backups")
		return
	}

	var backupPath string
	for _, b := range backups {
		if b.Name == backupID || b.Path == backupID {
			backupPath = b.Path
			break
		}
	}

	if backupPath == "" {
		respondError(w, r, http.StatusNotFound, "BACKUP_NOT_FOUND",
			"Backup archive not found")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	var triggeredBy *string
	if adminID != "" {
		triggeredBy = &adminID
	}

	jobID, err := mgr.RestoreAsync(ctx, backupPath, triggeredBy)
	if err != nil {
		s.logger.Error("restore failed to start", "error", err, "backup_path", backupPath)
		respondError(w, r, http.StatusInternalServerError, "RESTORE_ERROR", "Failed to start restore")
		return
	}

	respond(w, r, http.StatusAccepted, map[string]string{
		"job_id":      jobID,
		"backup_path": backupPath,
		"message":     "Restore job started",
	})
}
