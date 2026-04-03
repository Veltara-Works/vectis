package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// ── IP Warmup ──────────────────────────────────────────────────────────

type createWarmupRequest struct {
	IPAddress string `json:"ip_address"`
	Label     string `json:"label,omitempty"`
}

// handleListWarmup returns all IP warmup entries with status.
func (s *Server) handleListWarmup(w http.ResponseWriter, r *http.Request) {
	entries, err := s.ipWarmup.List(r.Context())
	if err != nil {
		s.logger.Error("list ip warmup failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list warmup entries")
		return
	}
	if entries == nil {
		entries = []repository.IPWarmup{}
	}

	// Add schedule info.
	type warmupEntry struct {
		repository.IPWarmup
		ScheduleLimit int     `json:"schedule_limit"` // recommended limit for current day
		UtilizationPct float64 `json:"utilization_pct"` // daily_sent / daily_limit * 100
	}

	result := make([]warmupEntry, len(entries))
	for i, e := range entries {
		utilization := float64(0)
		if e.DailyLimit > 0 {
			utilization = float64(e.DailySent) / float64(e.DailyLimit) * 100
		}
		result[i] = warmupEntry{
			IPWarmup:       e,
			ScheduleLimit:  repository.WarmupSchedule(e.WarmupDay),
			UtilizationPct: utilization,
		}
	}
	respond(w, r, http.StatusOK, result)
}

// handleCreateWarmup starts warmup tracking for a new IP.
func (s *Server) handleCreateWarmup(w http.ResponseWriter, r *http.Request) {
	var req createWarmupRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}
	if req.IPAddress == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "ip_address is required")
		return
	}

	// Check if already exists.
	existing, _ := s.ipWarmup.GetByIP(r.Context(), req.IPAddress)
	if existing != nil {
		respondError(w, r, http.StatusConflict, "ALREADY_EXISTS",
			"Warmup tracking already exists for this IP")
		return
	}

	entry, err := s.ipWarmup.Create(r.Context(), req.IPAddress, req.Label)
	if err != nil {
		s.logger.Error("create ip warmup failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create warmup entry")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "warmup.create", "ip_warmup", &entry.ID,
		map[string]any{"ip_address": req.IPAddress, "label": req.Label}, &ip)

	respond(w, r, http.StatusCreated, entry)
}

// handleDeleteWarmup removes warmup tracking for an IP.
func (s *Server) handleDeleteWarmup(w http.ResponseWriter, r *http.Request) {
	warmupID := chi.URLParam(r, "warmupID")
	if warmupID == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_ID", "Warmup ID is required")
		return
	}

	if err := s.ipWarmup.Delete(r.Context(), warmupID); err != nil {
		s.logger.Error("delete ip warmup failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete warmup entry")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "warmup.delete", "ip_warmup", &warmupID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"status": "deleted"})
}

// ── RBL Monitoring ─────────────────────────────────────────────────────

// handleRBLStatus returns the latest RBL check results for all server IPs.
func (s *Server) handleRBLStatus(w http.ResponseWriter, r *http.Request) {
	type rblIPStatus struct {
		IPAddress string               `json:"ip_address"`
		Checks    []repository.RBLCheck `json:"checks"`
		Listed    int                  `json:"listed_count"`
		Clean     bool                 `json:"clean"`
	}

	// Get unique IPs from warmup or configured IPs.
	var ips []string
	if s.rblMonitor != nil {
		ips = s.rblMonitor.IPs()
	}
	if len(ips) == 0 {
		respond(w, r, http.StatusOK, map[string]any{
			"status": "no_ips_configured",
			"ips":    []any{},
		})
		return
	}

	var statuses []rblIPStatus
	for _, ipAddr := range ips {
		checks, err := s.rblChecks.GetLatestByIP(r.Context(), ipAddr)
		if err != nil {
			s.logger.Error("get rbl status failed", "error", err, "ip", ipAddr)
			continue
		}
		listedCount := 0
		for _, c := range checks {
			if c.Listed {
				listedCount++
			}
		}
		statuses = append(statuses, rblIPStatus{
			IPAddress: ipAddr,
			Checks:    checks,
			Listed:    listedCount,
			Clean:     listedCount == 0,
		})
	}

	respond(w, r, http.StatusOK, map[string]any{
		"checked_at": time.Now().UTC().Format(time.RFC3339),
		"ips":        statuses,
	})
}

// handleRBLCheckNow triggers an immediate RBL check for all IPs.
func (s *Server) handleRBLCheckNow(w http.ResponseWriter, r *http.Request) {
	if s.rblMonitor == nil {
		respondError(w, r, http.StatusServiceUnavailable, "RBL_UNAVAILABLE",
			"RBL monitoring is not configured")
		return
	}

	results := s.rblMonitor.CheckNow(r.Context())

	listedCount := 0
	for _, c := range results {
		if c.Listed {
			listedCount++
		}
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "rbl.check", "system", nil,
		map[string]any{"checks": len(results), "listed": listedCount}, &ip)

	respond(w, r, http.StatusOK, map[string]any{
		"checks": results,
		"total":  len(results),
		"listed": listedCount,
	})
}

// ── FBL Reports ────────────────────────────────────────────────────────

type fblReportRequest struct {
	OriginalMessageID string         `json:"original_message_id,omitempty"`
	ReporterDomain    string         `json:"reporter_domain"`
	ComplaintType     string         `json:"complaint_type,omitempty"`
	FeedbackID        string         `json:"feedback_id,omitempty"`
	Details           map[string]any `json:"details,omitempty"`
}

// handleCreateFBLReport records an ISP feedback loop complaint.
// Can be called by the inbound processing pipeline or manually.
func (s *Server) handleCreateFBLReport(w http.ResponseWriter, r *http.Request) {
	var req fblReportRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if req.ReporterDomain == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "reporter_domain is required")
		return
	}

	complaintType := req.ComplaintType
	if complaintType == "" {
		complaintType = "abuse"
	}

	// Try to link to domain/mailbox via the original message.
	var domainID, mailboxID *string
	if req.OriginalMessageID != "" && s.messages != nil {
		msg, _ := s.messages.GetByMessageID(r.Context(), req.OriginalMessageID)
		if msg != nil {
			domainID = &msg.DomainID
			mailboxID = msg.MailboxID
		}
	}

	var detailsJSON []byte
	if req.Details != nil {
		detailsJSON = marshalJSONBytes(req.Details)
	}

	var feedbackID *string
	if req.FeedbackID != "" {
		feedbackID = &req.FeedbackID
	}
	var origMsgID *string
	if req.OriginalMessageID != "" {
		origMsgID = &req.OriginalMessageID
	}

	report := &repository.FBLReport{
		DomainID:          domainID,
		MailboxID:         mailboxID,
		OriginalMessageID: origMsgID,
		ReporterDomain:    req.ReporterDomain,
		ComplaintType:     complaintType,
		FeedbackID:        feedbackID,
		Details:           detailsJSON,
	}

	id, err := s.fblReports.Create(r.Context(), report)
	if err != nil {
		s.logger.Error("create fbl report failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create FBL report")
		return
	}

	// Log as abuse event if we identified the domain.
	if domainID != nil {
		action := "alert"
		s.abuseEvents.LogEvent(r.Context(), domainID, mailboxID, "fbl_complaint", "warn",
			map[string]any{
				"reporter": req.ReporterDomain,
				"type":     complaintType,
			}, &action)
	}

	respond(w, r, http.StatusCreated, map[string]string{"id": id})
}

// handleListFBLReports returns recent FBL reports.
func (s *Server) handleListFBLReports(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")

	if domainID != "" {
		if !s.canAccessDomain(r.Context(), domainID) {
			respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
			return
		}
		reports, err := s.fblReports.ListByDomain(r.Context(), domainID, 100)
		if err != nil {
			s.logger.Error("list fbl reports failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list FBL reports")
			return
		}
		if reports == nil {
			reports = []repository.FBLReport{}
		}
		respond(w, r, http.StatusOK, reports)
		return
	}

	reports, err := s.fblReports.ListRecent(r.Context(), 100)
	if err != nil {
		s.logger.Error("list fbl reports failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list FBL reports")
		return
	}
	if reports == nil {
		reports = []repository.FBLReport{}
	}
	respond(w, r, http.StatusOK, reports)
}

// marshalJSONBytes marshals a value to JSON bytes.
func marshalJSONBytes(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	return b
}
