package api

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// --- POST /api/v1/orchestrator/plan ---

func (s *Server) handleOrchestratorPlan(w http.ResponseWriter, r *http.Request) {
	if s.orchClient == nil {
		respondError(w, r, http.StatusServiceUnavailable, "ORCHESTRATOR_NOT_CONFIGURED",
			"Orchestrator client is not configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()

	plan, err := s.orchClient.Plan(ctx)
	if err != nil {
		s.logger.Error("orchestrator plan failed", "error", err)
		respondError(w, r, http.StatusBadGateway, "ORCHESTRATOR_ERROR", "Failed to generate update plan")
		return
	}

	respond(w, r, http.StatusOK, plan)
}

// --- POST /api/v1/orchestrator/apply ---

func (s *Server) handleOrchestratorApply(w http.ResponseWriter, r *http.Request) {
	if s.orchClient == nil {
		respondError(w, r, http.StatusServiceUnavailable, "ORCHESTRATOR_NOT_CONFIGURED",
			"Orchestrator client is not configured")
		return
	}

	force := r.URL.Query().Get("force") == "true"

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Minute)
	defer cancel()

	result, err := s.orchClient.Apply(ctx, force)
	if err != nil {
		s.logger.Error("orchestrator apply failed", "error", err)
		respondError(w, r, http.StatusBadGateway, "ORCHESTRATOR_ERROR", "Failed to apply update")
		return
	}

	respond(w, r, http.StatusOK, result)
}

// --- POST /api/v1/orchestrator/rollback ---

func (s *Server) handleOrchestratorRollback(w http.ResponseWriter, r *http.Request) {
	if s.orchClient == nil {
		respondError(w, r, http.StatusServiceUnavailable, "ORCHESTRATOR_NOT_CONFIGURED",
			"Orchestrator client is not configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Minute)
	defer cancel()

	result, err := s.orchClient.Rollback(ctx)
	if err != nil {
		s.logger.Error("orchestrator rollback failed", "error", err)
		respondError(w, r, http.StatusBadGateway, "ORCHESTRATOR_ERROR", "Failed to rollback update")
		return
	}

	respond(w, r, http.StatusOK, result)
}

// --- GET /api/v1/orchestrator/status ---

func (s *Server) handleOrchestratorStatus(w http.ResponseWriter, r *http.Request) {
	if s.orchClient == nil {
		respondError(w, r, http.StatusServiceUnavailable, "ORCHESTRATOR_NOT_CONFIGURED",
			"Orchestrator client is not configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	status, err := s.orchClient.Status(ctx)
	if err != nil {
		s.logger.Error("orchestrator status failed", "error", err)
		respondError(w, r, http.StatusBadGateway, "ORCHESTRATOR_ERROR", "Failed to retrieve orchestrator status")
		return
	}

	respond(w, r, http.StatusOK, status)
}

// --- GET /api/v1/orchestrator/history ---

type orchestratorHistoryEntry struct {
	ID          string     `json:"id"`
	Action      string     `json:"action"`
	Status      string     `json:"status"`
	PlanSummary string     `json:"plan_summary,omitempty"`
	Error       string     `json:"error,omitempty"`
	StartedAt   time.Time  `json:"started_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
	AdminID     string     `json:"admin_id,omitempty"`
}

func (s *Server) handleOrchestratorHistory(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	rows, err := s.db.Query(ctx, `
		SELECT id, action, status, plan_summary, error, started_at, completed_at, admin_id
		FROM orchestrator_history
		ORDER BY started_at DESC
		LIMIT 50
	`)
	if err != nil {
		s.logger.Error("orchestrator history query failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "DB_ERROR",
			"Failed to query orchestrator history")
		return
	}
	defer rows.Close()

	var entries []orchestratorHistoryEntry
	for rows.Next() {
		var e orchestratorHistoryEntry
		var planSummary, errMsg, adminID *string
		var completedAt *time.Time

		if err := rows.Scan(&e.ID, &e.Action, &e.Status, &planSummary, &errMsg, &e.StartedAt, &completedAt, &adminID); err != nil {
			s.logger.Error("orchestrator history scan failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "DB_ERROR",
				"Failed to read orchestrator history")
			return
		}

		if planSummary != nil {
			e.PlanSummary = *planSummary
		}
		if errMsg != nil {
			e.Error = *errMsg
		}
		if completedAt != nil {
			e.CompletedAt = completedAt
		}
		if adminID != nil {
			e.AdminID = *adminID
		}

		entries = append(entries, e)
	}

	if err := rows.Err(); err != nil {
		// If the table doesn't exist yet, return empty list rather than an error.
		if err == pgx.ErrNoRows {
			entries = []orchestratorHistoryEntry{}
		} else {
			s.logger.Error("orchestrator history rows error", "error", err)
			respondError(w, r, http.StatusInternalServerError, "DB_ERROR",
				"Failed to read orchestrator history")
			return
		}
	}

	if entries == nil {
		entries = []orchestratorHistoryEntry{}
	}

	respond(w, r, http.StatusOK, entries)
}
