package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/backup"
	"github.com/Veltara-Works/vectis/internal/repository"
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

// --- POST /api/v1/backup/incremental ---

func (s *Server) handleBackupIncremental(w http.ResponseWriter, r *http.Request) {
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

	jobID, backupType, err := mgr.CreateIncrementalAsync(ctx, triggeredBy)
	if err != nil {
		s.logger.Error("incremental backup create failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "BACKUP_ERROR", "Failed to create backup")
		return
	}

	respond(w, r, http.StatusAccepted, map[string]string{
		"job_id":  jobID,
		"type":    string(backupType),
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

	// Reject incremental archives (BAK-1): the restore path treats every archive
	// as a full snapshot and clears the maildir before unpacking, so restoring an
	// incremental alone would erase all mail older than its parent full backup.
	if backup.IsIncrementalArchiveName(backupPath) {
		respondError(w, r, http.StatusBadRequest, "INCREMENTAL_RESTORE_UNSUPPORTED",
			backup.ErrIncrementalRestore.Error())
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

// --- GET /api/v1/backup/settings ---

// backupSettingsResponse is the wire shape for GET / PUT /backup/settings.
// next_run is the next time the schedule will fire (omitted when disabled or
// the schedule is invalid). from_db reports whether the values came from the
// admin-UI override (true) or the file config defaults (false).
type backupSettingsResponse struct {
	Enabled    bool          `json:"enabled"`
	Schedule   string        `json:"schedule"`
	Timezone   string        `json:"timezone"`
	RetainDays int           `json:"retain_days"`
	FromDB     bool          `json:"from_db"`
	NextRun    *time.Time    `json:"next_run,omitempty"`
	Backup     *backupHealth `json:"last_successful_backup,omitempty"`
}

// backupHealth surfaces the last-successful-backup signal (C-1) on the
// authenticated settings endpoint — deliberately NOT on the public /health, so
// backup cadence is not exposed to unauthenticated callers. Status mirrors the
// monitor's decision: "never" (none on record), "stale" (older than the
// grace-adjusted expected interval), or "ok".
type backupHealth struct {
	Status        string     `json:"status"` // "ok" | "stale" | "never"
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	AgeSeconds    int64      `json:"age_seconds,omitempty"`
	MaxAgeSeconds int64      `json:"max_age_seconds,omitempty"` // grace-adjusted interval used as the stale threshold
}

func (s *Server) backupSettingsResponseFor(ctx context.Context, st backup.Settings) backupSettingsResponse {
	resp := backupSettingsResponse{
		Enabled:    st.Enabled,
		Schedule:   st.Schedule,
		Timezone:   st.Timezone,
		RetainDays: st.RetainDays,
		FromDB:     st.FromDB,
	}
	if st.Enabled {
		if next, err := backup.NextScheduledRun(st.Schedule, st.Timezone, time.Now()); err == nil {
			resp.NextRun = &next
		}
	}
	resp.Backup = s.backupHealthFor(ctx, st)
	return resp
}

// backupHealthFor computes the last-successful-backup health from the backup_jobs
// table and the effective schedule. Returns nil (field omitted) when the DB is
// unavailable or the query fails — a health read must never break the settings
// endpoint.
func (s *Server) backupHealthFor(ctx context.Context, st backup.Settings) *backupHealth {
	if s.db == nil {
		return nil
	}
	last, err := repository.NewBackupRepo(s.db).LatestCompleted(ctx)
	if err != nil {
		s.logger.Debug("backup settings: last-successful query failed", "error", err)
		return nil
	}
	if last == nil {
		return &backupHealth{Status: "never"}
	}
	h := &backupHealth{
		Status:      "ok",
		CompletedAt: last,
		AgeSeconds:  int64(time.Since(*last).Seconds()),
	}
	// Staleness only means something when a schedule is configured.
	if st.Enabled {
		if maxInterval, err := backup.ExpectedInterval(st.Schedule, st.Timezone, time.Now(), 8); err == nil {
			threshold := time.Duration(float64(maxInterval) * backup.StaleGraceFactor)
			h.MaxAgeSeconds = int64(threshold.Seconds())
			if time.Since(*last) > threshold {
				h.Status = "stale"
			}
		}
	}
	return h
}

func (s *Server) handleGetBackupSettings(w http.ResponseWriter, r *http.Request) {
	st := s.effectiveBackupSettings(r.Context())
	respond(w, r, http.StatusOK, s.backupSettingsResponseFor(r.Context(), st))
}

// --- PUT /api/v1/backup/settings ---

type updateBackupSettingsRequest struct {
	Enabled    bool   `json:"enabled"`
	Schedule   string `json:"schedule"`
	Timezone   string `json:"timezone"`
	RetainDays int    `json:"retain_days"`
}

func (s *Server) handleUpdateBackupSettings(w http.ResponseWriter, r *http.Request) {
	if s.db == nil {
		respondError(w, r, http.StatusServiceUnavailable, "BACKUP_NOT_CONFIGURED",
			"Database is not available")
		return
	}

	var req updateBackupSettingsRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	st := backup.Settings{
		Enabled:    req.Enabled,
		Schedule:   strings.TrimSpace(req.Schedule),
		Timezone:   strings.TrimSpace(req.Timezone),
		RetainDays: req.RetainDays,
	}
	if err := st.Validate(); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_BACKUP_SETTINGS", err.Error())
		return
	}

	adminID := getAdminID(r.Context())
	if err := backup.SaveSettings(r.Context(), s.db, s.logger, st, adminID); err != nil {
		s.logger.Error("save backup settings failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save backup settings")
		return
	}

	// Apply the new schedule/timezone immediately — no container restart.
	s.ReloadBackupScheduler()

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "backup.settings.update", "backup", nil,
		map[string]string{
			"enabled":     boolStr(st.Enabled),
			"schedule":    st.Schedule,
			"timezone":    st.Timezone,
			"retain_days": strconv.Itoa(st.RetainDays),
		}, &ip)

	st.FromDB = true
	respond(w, r, http.StatusOK, s.backupSettingsResponseFor(r.Context(), st))
}
