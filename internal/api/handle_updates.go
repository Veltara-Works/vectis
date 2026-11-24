package api

import (
	"context"
	"net/http"
	"time"

	"github.com/Veltara-Works/vectis/internal/orchestrator"
	"github.com/Veltara-Works/vectis/internal/updatecheck"
	"github.com/Veltara-Works/vectis/internal/version"
)

// updateStatusResponse is what the dashboard and Updates page show.
type updateStatusResponse struct {
	// Enabled is false when config.yaml sets updates.check: false.
	Enabled bool `json:"enabled"`
	// EmailEnabled is whether a new release is emailed to the admin.
	EmailEnabled bool `json:"email_enabled"`
	// Running is the version this API build reports.
	Running string `json:"running"`
	// Last is the most recent check; zero CheckedAt means none has run yet
	// (the first check runs 5–30 minutes after the API starts).
	Last updatecheck.State `json:"last"`
}

// --- GET /api/v1/system/updates ---
//
// Read-only: returns the last recorded update check. It never triggers a fetch
// (the background checker does that once a day), so loading the dashboard
// doesn't reach out to the internet.
func (s *Server) handleUpdateStatus(w http.ResponseWriter, r *http.Request) {
	resp := updateStatusResponse{
		Enabled:      s.cfg == nil || s.cfg.Updates.CheckEnabled(),
		EmailEnabled: s.cfg == nil || s.cfg.Updates.EmailEnabled(),
		Running:      version.Version,
	}
	if s.vk != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		st, err := updatecheck.ValkeyStore{VK: s.vk}.Load(ctx)
		if err != nil {
			s.logger.Warn("update status: could not load last check", "error", err)
		} else {
			resp.Last = st
		}
	}
	resp.Last = reconcileWithRunning(resp.Last, resp.Running)
	// With the check turned off, a result stored before that is not offered:
	// it can't be refreshed, so it would go stale.
	if !resp.Enabled {
		resp.Last.UpdateAvailable = false
	}
	respond(w, r, http.StatusOK, resp)
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
