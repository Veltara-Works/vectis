package api

import (
	"net/http"
	"time"
)

// handleDomainAnalytics returns per-domain mail statistics over a time range.
// Query params: domain_id (required for domain_admin), period (1h, 24h, 7d, 30d), granularity (hourly, daily)
func (s *Server) handleDomainAnalytics(w http.ResponseWriter, r *http.Request) {
	domainID := r.URL.Query().Get("domain_id")
	period := r.URL.Query().Get("period")
	granularity := r.URL.Query().Get("granularity")

	if period == "" {
		period = "24h"
	}
	if granularity == "" {
		granularity = "hourly"
	}

	now := time.Now().UTC()
	var from time.Time
	switch period {
	case "1h":
		from = now.Add(-1 * time.Hour)
	case "24h":
		from = now.Add(-24 * time.Hour)
	case "7d":
		from = now.Add(-7 * 24 * time.Hour)
	case "30d":
		from = now.Add(-30 * 24 * time.Hour)
	default:
		respondError(w, r, http.StatusBadRequest, "INVALID_PERIOD",
			"Valid periods: 1h, 24h, 7d, 30d")
		return
	}

	// Domain access check.
	if domainID != "" && !s.canAccessDomain(r.Context(), domainID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
		return
	}

	allowedIDs := s.getAllowedDomainIDs(r.Context())
	if allowedIDs != nil && domainID == "" && len(allowedIDs) == 0 {
		respond(w, r, http.StatusOK, map[string]any{"stats": []any{}, "period": period})
		return
	}

	// Single domain detailed stats.
	if domainID != "" {
		switch granularity {
		case "hourly":
			stats, err := s.mailStats.GetHourly(r.Context(), domainID, from, now)
			if err != nil {
				s.logger.Error("get hourly analytics failed", "error", err)
				respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get analytics")
				return
			}
			respond(w, r, http.StatusOK, map[string]any{
				"domain_id":   domainID,
				"period":      period,
				"granularity": granularity,
				"stats":       stats,
			})
		case "daily":
			stats, err := s.mailStats.GetDailyAggregate(r.Context(), domainID, from, now)
			if err != nil {
				s.logger.Error("get daily analytics failed", "error", err)
				respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get analytics")
				return
			}
			respond(w, r, http.StatusOK, map[string]any{
				"domain_id":   domainID,
				"period":      period,
				"granularity": granularity,
				"stats":       stats,
			})
		default:
			respondError(w, r, http.StatusBadRequest, "INVALID_GRANULARITY",
				"Valid granularities: hourly, daily")
		}
		return
	}

	// All domains aggregate summary.
	agg, err := s.mailStats.GetAllDomainsAggregate(r.Context(), allowedIDs, from, now)
	if err != nil {
		s.logger.Error("get all domains analytics failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get analytics")
		return
	}

	// Compute totals.
	var totalSent, totalReceived, totalBounced, totalSpam, totalFailed int
	var totalSize int64
	for _, a := range agg {
		totalSent += a.Sent
		totalReceived += a.Received
		totalBounced += a.Bounced
		totalSpam += a.Spam
		totalFailed += a.Failed
		totalSize += a.SizeBytes
	}

	bounceRate := float64(0)
	if totalSent > 0 {
		bounceRate = float64(totalBounced) / float64(totalSent) * 100
	}
	spamRate := float64(0)
	if totalReceived > 0 {
		spamRate = float64(totalSpam) / float64(totalReceived) * 100
	}

	respond(w, r, http.StatusOK, map[string]any{
		"period": period,
		"totals": map[string]any{
			"sent":         totalSent,
			"received":     totalReceived,
			"bounced":      totalBounced,
			"spam":         totalSpam,
			"failed":       totalFailed,
			"size_bytes":   totalSize,
			"bounce_rate":  bounceRate,
			"spam_rate":    spamRate,
		},
		"domains": agg,
	})
}
