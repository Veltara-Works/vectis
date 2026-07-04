package api

import (
	"net/http"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"golang.org/x/sys/unix"
)

// allowedServices is the set of service names accepted by the system endpoints.
var allowedServices = map[string]string{
	"postfix":  "vectis-postfix",
	"dovecot":  "vectis-dovecot",
	"rspamd":   "vectis-rspamd",
	"clamav":   "vectis-clamav",
	"postgres": "vectis-postgres",
	"valkey":   "vectis-valkey",
	"traefik":  "vectis-traefik",
}

// --- GET /api/v1/health/{service} ---

type serviceHealthDetail struct {
	Service      string `json:"service"`
	Status       string `json:"status"`
	Container    string `json:"container_state,omitempty"`
	Health       string `json:"health,omitempty"`
	Uptime       string `json:"uptime,omitempty"`
	RestartCount int    `json:"restart_count"`
	ResponseMs   int64  `json:"response_ms,omitempty"`
}

func (s *Server) handleServiceHealth(w http.ResponseWriter, r *http.Request) {
	service := chi.URLParam(r, "service")
	container, ok := allowedServices[service]
	if !ok {
		respondError(w, r, http.StatusBadRequest, "INVALID_SERVICE",
			"Unknown service: "+service+". Allowed: postfix, dovecot, rspamd, clamav, postgres, valkey, traefik")
		return
	}

	result := serviceHealthDetail{Service: service}

	// For postgres and valkey, do direct connectivity checks (same pattern as handle_health.go).
	switch service {
	case "postgres":
		start := time.Now()
		if err := s.db.Ping(r.Context()); err != nil {
			result.Status = "unhealthy"
			result.ResponseMs = time.Since(start).Milliseconds()
		} else {
			result.Status = "healthy"
			result.ResponseMs = time.Since(start).Milliseconds()
		}
	case "valkey":
		start := time.Now()
		cmd := s.vk.B().Ping().Build()
		if err := s.vk.Do(r.Context(), cmd).Error(); err != nil {
			result.Status = "unhealthy"
			result.ResponseMs = time.Since(start).Milliseconds()
		} else {
			result.Status = "healthy"
			result.ResponseMs = time.Since(start).Milliseconds()
		}
	}

	// Always try to get container-level detail from Docker.
	out, err := exec.Command("docker", "inspect", "--format",
		`{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.StartedAt}}|{{.RestartCount}}`,
		container).Output()
	if err != nil {
		// If we already have a direct-check result, keep it; otherwise mark not found.
		if result.Status == "" {
			result.Status = "not_found"
		}
		result.Container = "not found"
		respond(w, r, http.StatusOK, result)
		return
	}

	parts := strings.Split(strings.TrimSpace(string(out)), "|")
	if len(parts) >= 4 {
		result.Container = parts[0]
		result.Health = parts[1]

		if startedAt, parseErr := time.Parse(time.RFC3339Nano, parts[2]); parseErr == nil {
			result.Uptime = formatDuration(time.Since(startedAt))
		}

		if rc, convErr := strconv.Atoi(parts[3]); convErr == nil {
			result.RestartCount = rc
		}
	}

	// For non-postgres/valkey services, derive status from container health.
	if result.Status == "" {
		if result.Health == "healthy" || result.Health == "none" {
			if result.Container == "running" {
				result.Status = "healthy"
			} else {
				result.Status = "unhealthy"
			}
		} else {
			result.Status = "unhealthy"
		}
	}

	respond(w, r, http.StatusOK, result)
}

// --- GET /api/v1/logs/{service} ---

type serviceLogsResponse struct {
	Service string   `json:"service"`
	Lines   []string `json:"lines"`
	Count   int      `json:"count"`
}

func (s *Server) handleServiceLogs(w http.ResponseWriter, r *http.Request) {
	service := chi.URLParam(r, "service")
	container, ok := allowedServices[service]
	if !ok {
		respondError(w, r, http.StatusBadRequest, "INVALID_SERVICE",
			"Unknown service: "+service+". Allowed: postfix, dovecot, rspamd, clamav, postgres, valkey, traefik")
		return
	}

	// Parse query params.
	tail := 100
	if t := r.URL.Query().Get("tail"); t != "" {
		if v, err := strconv.Atoi(t); err == nil && v > 0 {
			if v > 10000 {
				v = 10000
			}
			tail = v
		}
	}
	since := r.URL.Query().Get("since")

	// Build docker logs command.
	args := []string{"logs", "--tail", strconv.Itoa(tail)}
	if since != "" {
		args = append(args, "--since", since)
	}
	args = append(args, container)

	// Docker writes logs to both stdout and stderr; capture both.
	cmd := exec.Command("docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		s.logger.Error("failed to retrieve service logs", "service", service, "error", err)
		respondError(w, r, http.StatusInternalServerError, "LOGS_ERROR",
			"Failed to retrieve logs for "+service)
		return
	}

	raw := strings.TrimRight(string(out), "\n")
	var lines []string
	if raw != "" {
		lines = strings.Split(raw, "\n")
	} else {
		lines = []string{}
	}

	respond(w, r, http.StatusOK, serviceLogsResponse{
		Service: service,
		Lines:   lines,
		Count:   len(lines),
	})
}

// --- GET /api/v1/metrics ---

type metricsResponse struct {
	MailQueue   *mailQueueMetrics `json:"mail_queue,omitempty"`
	Disk        *diskMetrics      `json:"disk,omitempty"`
	CollectedAt time.Time         `json:"collected_at"`
}

type mailQueueMetrics struct {
	Length int    `json:"length"`
	Error  string `json:"error,omitempty"`
}

type diskMetrics struct {
	Path       string  `json:"path"`
	TotalBytes uint64  `json:"total_bytes"`
	FreeBytes  uint64  `json:"free_bytes"`
	UsedBytes  uint64  `json:"used_bytes"`
	UsedPct    float64 `json:"used_pct"`
	Error      string  `json:"error,omitempty"`
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	result := metricsResponse{
		CollectedAt: time.Now().UTC(),
	}

	// Mail queue length via postqueue -j (each line is a JSON object for one message).
	result.MailQueue = getMailQueueMetrics()

	// Disk usage for /var/vectis/mail.
	result.Disk = getDiskMetrics("/var/vectis/mail")

	respond(w, r, http.StatusOK, result)
}

func getMailQueueMetrics() *mailQueueMetrics {
	mq := &mailQueueMetrics{}

	out, err := exec.Command("docker", "exec", "vectis-postfix", "postqueue", "-j").CombinedOutput()
	if err != nil {
		// Fallback: try mailq and count entries.
		outFallback, errFallback := exec.Command("docker", "exec", "vectis-postfix", "mailq").CombinedOutput()
		if errFallback != nil {
			mq.Error = "unable to query mail queue"
			return mq
		}
		// mailq output: "Mail queue is empty" or lines with queue IDs.
		content := strings.TrimSpace(string(outFallback))
		if strings.Contains(content, "Mail queue is empty") {
			mq.Length = 0
		} else {
			// Count lines that start with a queue ID (hex uppercase, 10+ chars).
			count := 0
			for _, line := range strings.Split(content, "\n") {
				trimmed := strings.TrimSpace(line)
				if len(trimmed) > 10 && isHexPrefix(trimmed) {
					count++
				}
			}
			mq.Length = count
		}
		return mq
	}

	// postqueue -j outputs one JSON object per line per queued message.
	content := strings.TrimSpace(string(out))
	if content == "" {
		mq.Length = 0
	} else {
		mq.Length = len(strings.Split(content, "\n"))
	}
	return mq
}

func getDiskMetrics(path string) *diskMetrics {
	dm := &diskMetrics{Path: path}

	var stat unix.Statfs_t
	if err := unix.Statfs(path, &stat); err != nil {
		dm.Error = "unable to stat " + path + ": " + err.Error()
		return dm
	}

	dm.TotalBytes = stat.Blocks * uint64(stat.Bsize)
	dm.FreeBytes = stat.Bavail * uint64(stat.Bsize)
	dm.UsedBytes = dm.TotalBytes - dm.FreeBytes
	if dm.TotalBytes > 0 {
		dm.UsedPct = float64(dm.UsedBytes) / float64(dm.TotalBytes) * 100
	}

	return dm
}

// isHexPrefix returns true if the first character of s is a hex digit (used for mailq parsing).
func isHexPrefix(s string) bool {
	if len(s) == 0 {
		return false
	}
	c := s[0]
	return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')
}

// formatDuration formats a duration into a human-readable string like "3d 5h" or "2h 15m".
func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	mins := int(d.Minutes()) % 60

	if days > 0 {
		return strconv.Itoa(days) + "d " + strconv.Itoa(hours) + "h"
	}
	if hours > 0 {
		return strconv.Itoa(hours) + "h " + strconv.Itoa(mins) + "m"
	}
	return strconv.Itoa(mins) + "m"
}
