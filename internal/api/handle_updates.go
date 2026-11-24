package api

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/Veltara-Works/vectis/internal/orchestrator"
	"github.com/Veltara-Works/vectis/internal/updatecheck"
	"github.com/Veltara-Works/vectis/internal/version"
)

// updateStatusResponse is what the dashboard and Updates page show.
type updateStatusResponse struct {
	// Enabled / EmailEnabled are the effective switches (kept at the top level
	// for the dashboard banner).
	Enabled      bool `json:"enabled"`
	EmailEnabled bool `json:"email_enabled"`
	// Settings is the full switch state for the Updates page, including
	// whether config.yaml locks a switch off and whether switches are
	// available yet (migration 000028).
	Settings updatecheck.Settings `json:"settings"`
	// Running is the version this API build reports.
	Running string `json:"running"`
	// Last is the most recent check; zero CheckedAt means none has run yet
	// (the first check runs 5–30 minutes after the API starts).
	Last updatecheck.State `json:"last"`
}

// --- GET /api/v1/system/updates ---
//
// Read-only: returns the switches and the last recorded update check. It never
// triggers a fetch (the background checker does that once a day), so loading
// the dashboard doesn't reach out to the internet.
func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	respond(w, r, http.StatusOK, s.updateStatus(r.Context()))
}

func (s *Server) updateStatus(ctx context.Context) updateStatusResponse {
	set := s.updateCheckSettings(ctx)
	resp := updateStatusResponse{
		Enabled:      set.CheckEnabled,
		EmailEnabled: set.EmailEnabled,
		Settings:     set,
		Running:      version.Version,
	}
	if s.vk != nil {
		vctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		st, err := updatecheck.ValkeyStore{VK: s.vk}.Load(vctx)
		if err != nil {
			s.logger.Warn("update status: could not load last check", "error", err)
		} else {
			resp.Last = st
		}
	}
	resp.Last = reconcileWithRunning(resp.Last, resp.Running)
	// With the check switched off, a result stored before that is not offered:
	// it can't be refreshed, so it would go stale.
	if !resp.Enabled {
		resp.Last.UpdateAvailable = false
	}
	return resp
}

type updateCheckSettingsRequest struct {
	CheckEnabled *bool `json:"check_enabled"`
	EmailEnabled *bool `json:"email_enabled"`
}

// --- PUT /api/v1/system/updates/settings ---
//
// Saves the dashboard switches. Takes effect at the next check, without a
// restart; switching the check on runs one straight away. A switch that
// config.yaml locks off can't be turned on here (409).
func (s *Server) handleUpdateCheckSettings(w http.ResponseWriter, r *http.Request) {
	var req updateCheckSettingsRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}
	if req.CheckEnabled == nil && req.EmailEnabled == nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_SETTINGS", "Set check_enabled and/or email_enabled")
		return
	}
	cur := s.updateCheckSettings(r.Context())
	if !cur.Switchable {
		respondError(w, r, http.StatusConflict, "SETTING_UNAVAILABLE",
			"These switches become available after the next update. Until then, use updates: in config.yaml.")
		return
	}
	// Start from the saved choice (not the effective values), so a partial
	// request keeps the other switch, and a config.yaml lock doesn't overwrite
	// what the admin chose underneath it.
	next := updatecheck.Stored{CheckEnabled: true, EmailEnabled: true}
	if stored, _, err := updatecheck.LoadStored(r.Context(), s.db); err == nil && stored != nil {
		next = *stored
	}
	if req.CheckEnabled != nil {
		if *req.CheckEnabled && cur.CheckLocked {
			respondError(w, r, http.StatusConflict, "SETTING_LOCKED",
				"The update check is turned off in /etc/vectis/config.yaml (updates.check: false), so it can't be turned on here.")
			return
		}
		next.CheckEnabled = *req.CheckEnabled
	}
	if req.EmailEnabled != nil {
		if *req.EmailEnabled && cur.EmailLocked {
			respondError(w, r, http.StatusConflict, "SETTING_LOCKED",
				"Update emails are turned off in /etc/vectis/config.yaml (updates.email or updates.check: false), so they can't be turned on here.")
			return
		}
		next.EmailEnabled = *req.EmailEnabled
	}

	adminID := getAdminID(r.Context())
	if err := updatecheck.SaveStored(r.Context(), s.db, next, adminID); err != nil {
		if errors.Is(err, updatecheck.ErrNotSwitchable) {
			respondError(w, r, http.StatusConflict, "SETTING_UNAVAILABLE",
				"These switches become available after the next update. Until then, use updates: in config.yaml.")
			return
		}
		s.logger.Error("save update-check settings", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to save the update-check settings")
		return
	}

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "updates.settings.update", "updates", nil,
		map[string]string{
			"check_enabled": boolStr(next.CheckEnabled),
			"email_enabled": boolStr(next.EmailEnabled),
		}, &ip)

	if next.CheckEnabled && !cur.CheckEnabled && s.updateChecker != nil {
		s.updateChecker.Kick()
	}
	respond(w, r, http.StatusOK, s.updateStatus(r.Context()))
}

// reconcileWithRunning drops a stale "update available". The stored state is
// from the last daily check; after an update, until the next check runs, it can
// still name a "latest" this server has now reached or passed. The running
// build is authoritative, so that update is no longer offered.
func reconcileWithRunning(st updatecheck.State, running string) updatecheck.State {
	if !st.UpdateAvailable || !orchestrator.ValidReleaseTag(running) || !orchestrator.ValidReleaseTag(st.Latest) {
		return st
	}
	if cmp, err := orchestrator.CompareReleaseTags(st.Latest, running); err == nil && cmp <= 0 {
		st.UpdateAvailable = false
	}
	return st
}
