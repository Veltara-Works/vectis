package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// logServiceNameRe restricts the `service` filter to a safe charset so a
// caller-supplied value can't break out of the LogQL stream selector (P3-M3).
var logServiceNameRe = regexp.MustCompile(`^[a-z0-9-]+$`)

// handleLogSearch queries the Loki API for log entries matching the given filters.
// Query params: query (LogQL), service (postfix|dovecot|...), start, end, limit, pattern
// Falls back to Docker logs if Loki is not enabled.
func (s *Server) handleLogSearch(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	pattern := r.URL.Query().Get("pattern")
	startStr := r.URL.Query().Get("start")
	endStr := r.URL.Query().Get("end")
	limitStr := r.URL.Query().Get("limit")
	logqlQuery := r.URL.Query().Get("query")

	if limitStr == "" {
		limitStr = "500"
	}

	if service != "" && !logServiceNameRe.MatchString(service) {
		respondError(w, r, http.StatusBadRequest, "INVALID_SERVICE",
			"service may only contain lowercase letters, digits, and hyphens")
		return
	}

	// If Loki is enabled, query Loki API.
	if s.cfg != nil && s.cfg.Observability.LokiEnabled {
		results, err := s.queryLoki(r, logqlQuery, service, pattern, startStr, endStr, limitStr)
		if err != nil {
			s.logger.Error("loki query failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "LOKI_ERROR", "Failed to query logs")
			return
		}
		respond(w, r, http.StatusOK, results)
		return
	}

	// Fallback: Docker logs (existing mechanism, enhanced with pattern grep).
	if service == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "service is required when Loki is not enabled")
		return
	}

	// Delegate to the existing handleServiceLogs with grep support.
	if pattern != "" {
		r.URL.RawQuery = fmt.Sprintf("tail=500&grep=%s", url.QueryEscape(pattern))
	}
	// Rewrite to use existing log handler via internal redirect.
	respondError(w, r, http.StatusOK, "LOKI_DISABLED",
		"Loki is not enabled. Use GET /api/v1/logs/{service}?tail=N&grep=pattern for Docker log access.")
}

func (s *Server) queryLoki(r *http.Request, logqlQuery, service, pattern, startStr, endStr, limitStr string) (any, error) {
	lokiBase := "http://vectis-loki:3100"

	// Build LogQL query if not provided directly.
	if logqlQuery == "" {
		if service != "" {
			logqlQuery = fmt.Sprintf(`{container_name="vectis-%s"}`, service)
		} else {
			logqlQuery = `{container_name=~"vectis-.*"}`
		}
		if pattern != "" {
			// Escape for the LogQL double-quoted string literal so a
			// caller-supplied pattern can't break out and inject operators (P3-M3).
			esc := strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(pattern)
			logqlQuery += fmt.Sprintf(` |~ "%s"`, esc)
		}
	}

	// Build Loki query_range URL.
	params := url.Values{}
	params.Set("query", logqlQuery)
	params.Set("limit", limitStr)
	params.Set("direction", "backward")

	if startStr != "" {
		params.Set("start", startStr)
	} else {
		params.Set("start", fmt.Sprintf("%d", time.Now().Add(-1*time.Hour).UnixNano()))
	}
	if endStr != "" {
		params.Set("end", endStr)
	} else {
		params.Set("end", fmt.Sprintf("%d", time.Now().UnixNano()))
	}

	lokiURL := fmt.Sprintf("%s/loki/api/v1/query_range?%s", lokiBase, params.Encode())

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, lokiURL, nil)
	if err != nil {
		return nil, fmt.Errorf("build loki request: %w", err)
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("loki request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5 MB limit
	if err != nil {
		return nil, fmt.Errorf("read loki response: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("loki returned %d: %s", resp.StatusCode, string(body))
	}

	var result any
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse loki response: %w", err)
	}

	return result, nil
}
