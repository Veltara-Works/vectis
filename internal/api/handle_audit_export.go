package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// handleExportAudit exports audit log entries as CSV or JSON for compliance archival.
// Query params: format (csv|json, default json), from, to (RFC3339 dates),
//   action, resource_type, admin_id (optional filters)
func (s *Server) handleExportAudit(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	fromStr := r.URL.Query().Get("from")
	toStr := r.URL.Query().Get("to")
	action := r.URL.Query().Get("action")
	resourceType := r.URL.Query().Get("resource_type")
	adminID := r.URL.Query().Get("admin_id")

	// Default: last 90 days.
	to := time.Now().UTC()
	from := to.Add(-90 * 24 * time.Hour)

	if fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			from = t
		}
	}
	if toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			to = t
		}
	}

	// Fetch all entries in the range (up to 10000 for export).
	query := `SELECT id, admin_id, action, resource_type, resource_id, details, ip_address, created_at
		 FROM audit_log WHERE created_at >= $1 AND created_at <= $2`
	args := []any{from, to}
	argIdx := 3

	if action != "" {
		query += fmt.Sprintf(" AND action = $%d", argIdx)
		args = append(args, action)
		argIdx++
	}
	if resourceType != "" {
		query += fmt.Sprintf(" AND resource_type = $%d", argIdx)
		args = append(args, resourceType)
		argIdx++
	}
	if adminID != "" {
		query += fmt.Sprintf(" AND admin_id = $%d", argIdx)
		args = append(args, adminID)
		argIdx++
	}

	query += " ORDER BY created_at ASC LIMIT 10000"

	rows, err := s.db.Query(r.Context(), query, args...)
	if err != nil {
		s.logger.Error("export audit failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to export audit log")
		return
	}
	defer rows.Close()

	type exportEntry struct {
		ID           string `json:"id" csv:"id"`
		AdminID      string `json:"admin_id" csv:"admin_id"`
		Action       string `json:"action" csv:"action"`
		ResourceType string `json:"resource_type" csv:"resource_type"`
		ResourceID   string `json:"resource_id" csv:"resource_id"`
		Details      string `json:"details" csv:"details"`
		IPAddress    string `json:"ip_address" csv:"ip_address"`
		CreatedAt    string `json:"created_at" csv:"created_at"`
	}

	var entries []exportEntry
	for rows.Next() {
		var e exportEntry
		var adminPtr, resourcePtr, ipPtr *string
		var details json.RawMessage
		var createdAt time.Time

		if err := rows.Scan(&e.ID, &adminPtr, &e.Action, &e.ResourceType, &resourcePtr, &details, &ipPtr, &createdAt); err != nil {
			continue
		}
		if adminPtr != nil {
			e.AdminID = *adminPtr
		}
		if resourcePtr != nil {
			e.ResourceID = *resourcePtr
		}
		if ipPtr != nil {
			e.IPAddress = *ipPtr
		}
		if details != nil {
			e.Details = string(details)
		}
		e.CreatedAt = createdAt.Format(time.RFC3339)
		entries = append(entries, e)
	}

	// Audit the export action itself.
	reqAdminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &reqAdminID, "audit.export", "system", nil,
		map[string]any{"format": format, "from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339), "count": len(entries)}, &ip)

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=\"vectis-audit-%s-to-%s.csv\"",
				from.Format("20060102"), to.Format("20060102")))

		writer := csv.NewWriter(w)
		writer.Write([]string{"id", "admin_id", "action", "resource_type", "resource_id", "details", "ip_address", "created_at"})
		for _, e := range entries {
			writer.Write([]string{e.ID, e.AdminID, e.Action, e.ResourceType, e.ResourceID, e.Details, e.IPAddress, e.CreatedAt})
		}
		writer.Flush()

	default: // json
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("attachment; filename=\"vectis-audit-%s-to-%s.json\"",
				from.Format("20060102"), to.Format("20060102")))
		if err := json.NewEncoder(w).Encode(map[string]any{
			"exported_at": time.Now().UTC().Format(time.RFC3339),
			"from":        from.Format(time.RFC3339),
			"to":          to.Format(time.RFC3339),
			"count":       len(entries),
			"entries":     entries,
		}); err != nil {
			s.logger.Error("failed to encode audit export response", "error", err)
		}
	}
}
