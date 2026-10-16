package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/mail"
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
		ScheduleLimit  int       `json:"schedule_limit"`  // recommended limit for current day
		UtilizationPct float64   `json:"utilization_pct"` // daily_sent / daily_limit * 100
		DaysTotal      int       `json:"days_total"`      // length of the schedule
		NextResetAt    time.Time `json:"next_reset_at"`   // when daily_sent resets and the next day starts
	}

	result := make([]warmupEntry, len(entries))
	for i, e := range entries {
		utilization := float64(0)
		if e.DailyLimit > 0 {
			utilization = float64(e.DailySent) / float64(e.DailyLimit) * 100
		}
		e.IPAddress = warmupIP(e.IPAddress)
		result[i] = warmupEntry{
			IPWarmup:       e,
			ScheduleLimit:  repository.WarmupSchedule(e.WarmupDay),
			UtilizationPct: utilization,
			DaysTotal:      mail.WarmupDays,
			NextResetAt:    e.LastResetAt.Add(24 * time.Hour),
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
	req.IPAddress = strings.TrimSpace(req.IPAddress)
	if req.IPAddress == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "ip_address is required")
		return
	}
	if net.ParseIP(req.IPAddress) == nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_IP", "ip_address must be an IPv4 or IPv6 address")
		return
	}

	// Check if already exists.
	existing, _ := s.ipWarmup.GetByIP(r.Context(), req.IPAddress)
	if existing != nil {
		respondError(w, r, http.StatusConflict, "ALREADY_EXISTS",
			"Warmup tracking already exists for this IP")
		return
	}
	// The server sends from one IP, and the daily limit applies to all outbound
	// mail, so only one warmup can run at a time. The check and the insert are
	// one locked transaction, so two concurrent requests can't both start one.
	entry, active, err := s.ipWarmup.CreateIfNoneActive(r.Context(), req.IPAddress, req.Label)
	if err != nil {
		s.logger.Error("create ip warmup failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create warmup entry")
		return
	}
	if active != nil {
		respondError(w, r, http.StatusConflict, "WARMUP_ACTIVE",
			"A warmup is already running for "+warmupIP(active.IPAddress)+"; cancel it before starting another")
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

// rblCheckView is an RBL check as the API returns it: the stored result plus
// the list's display name and delisting page.
type rblCheckView struct {
	repository.RBLCheck
	ListName  string `json:"list_name"`
	DelistURL string `json:"delist_url,omitempty"`
}

// viewRBLChecks returns one view per checked list, in the monitor's list
// order. A list with no stored result (a run still in progress, or a failed
// write) is shown as unknown, so a partial set can never read as all-clear.
func viewRBLChecks(checks []repository.RBLCheck) (views []rblCheckView, listed, unknown int) {
	byZone := make(map[string]repository.RBLCheck, len(checks))
	for _, c := range checks {
		byZone[c.RBLName] = c
	}
	views = []rblCheckView{}
	for _, l := range mail.DefaultBlocklists {
		c, ok := byZone[l.Zone]
		if !ok {
			reason := "not checked yet"
			c = repository.RBLCheck{RBLName: l.Zone, Status: repository.RBLStatusUnknown, Response: &reason}
		}
		switch c.Status {
		case repository.RBLStatusListed:
			listed++
		case repository.RBLStatusUnknown:
			unknown++
		}
		views = append(views, rblCheckView{RBLCheck: c, ListName: l.Name, DelistURL: l.DelistURL})
	}
	return views, listed, unknown
}

// handleRBLStatus returns the latest RBL check results for the server's IPs.
// clean is true only when every list answered and none lists the IP; an
// unknown result is never reported as clean.
func (s *Server) handleRBLStatus(w http.ResponseWriter, r *http.Request) {
	type rblIPStatus struct {
		IPAddress string         `json:"ip_address"`
		Checks    []rblCheckView `json:"checks"`
		Listed    int            `json:"listed_count"`
		Unknown   int            `json:"unknown_count"`
		Clean     bool           `json:"clean"`
	}

	var ips []string
	if s.rblMonitor != nil {
		ips = s.rblMonitor.IPs()
	}
	if len(ips) == 0 {
		respond(w, r, http.StatusOK, map[string]any{
			"status": "no_ips_yet",
			"ips":    []any{},
		})
		return
	}

	statuses := []rblIPStatus{}
	for _, ipAddr := range ips {
		checks, err := s.rblChecks.GetLatestByIP(r.Context(), ipAddr)
		if err != nil {
			s.logger.Error("get rbl status failed", "error", err, "ip", ipAddr)
			continue
		}
		views, listed, unknown := viewRBLChecks(checks)
		statuses = append(statuses, rblIPStatus{
			IPAddress: ipAddr,
			Checks:    views,
			Listed:    listed,
			Unknown:   unknown,
			Clean:     listed == 0 && unknown == 0,
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

	// One row per (IP, list) actually checked in this run.
	// The DNS work is capped at 20 s, leaving room within the server's 30 s
	// WriteTimeout to store the results (CheckNow stores them under its own
	// deadline) and respond. Lookups still running at 20 s are recorded as
	// unknown.
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	results, err := s.rblMonitor.CheckNow(ctx)
	var discoveryErr *mail.DiscoveryError
	if errors.As(err, &discoveryErr) {
		s.logger.Warn("rbl check: no server IP to check", "error", err)
		respondError(w, r, http.StatusServiceUnavailable, "RBL_DISCOVERY_FAILED",
			"Could not determine this server's IP address to check: "+discoveryErr.Err.Error())
		return
	}
	if err != nil {
		s.logger.Error("rbl check: results not stored", "error", err)
		respondError(w, r, http.StatusInternalServerError, "RBL_STORE_FAILED",
			"The blocklist check ran but some results could not be saved")
		return
	}
	views := make([]rblCheckView, 0, len(results))
	listed, unknown := 0, 0
	for _, c := range results {
		v := rblCheckView{RBLCheck: c, ListName: c.RBLName}
		if l, ok := mail.BlocklistByZone(c.RBLName); ok {
			v.ListName, v.DelistURL = l.Name, l.DelistURL
		}
		switch c.Status {
		case repository.RBLStatusListed:
			listed++
		case repository.RBLStatusUnknown:
			unknown++
		}
		views = append(views, v)
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "rbl.check", "system", nil,
		map[string]any{"checks": len(views), "listed": listed, "unknown": unknown}, &ip)

	respond(w, r, http.StatusOK, map[string]any{
		"checks":  views,
		"total":   len(views),
		"listed":  listed,
		"unknown": unknown,
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

	// No domain_id: return recent reports scoped to the caller's domains (K3).
	// getAllowedDomainIDs is nil for unrestricted principals (all domains) and a
	// non-nil allow-list otherwise, filtered in-query before the LIMIT.
	reports, err := s.fblReports.ListRecent(r.Context(), 100, s.getAllowedDomainIDs(r.Context()))
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
