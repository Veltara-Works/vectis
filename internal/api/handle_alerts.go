package api

import (
	"net/http"
)

// handleListAlerts returns all currently active (unresolved) alerts.
func (s *Server) handleListAlerts(w http.ResponseWriter, r *http.Request) {
	alerts, err := s.alerts.ListActive(r.Context())
	if err != nil {
		s.logger.Error("failed to list alerts", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list alerts")
		return
	}
	respond(w, r, http.StatusOK, alerts)
}

// handleRunHealthCheck triggers an immediate health check cycle.
func (s *Server) handleRunHealthCheck(w http.ResponseWriter, r *http.Request) {
	if s.monitor == nil {
		respondError(w, r, http.StatusServiceUnavailable, "MONITOR_NOT_RUNNING", "Health monitor is not active")
		return
	}
	s.monitor.RunCheck(r.Context())
	respond(w, r, http.StatusOK, map[string]string{"status": "check_completed"})
}
