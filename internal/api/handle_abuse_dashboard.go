package api

import (
	"net/http"

	"github.com/Veltara-Works/vectis/internal/repository"
)

type abuseDashboard struct {
	DomainRates  []domainRate           `json:"domain_rates"`
	RecentEvents []repository.AbuseEvent `json:"recent_events"`
}

type domainRate struct {
	DomainID    string `json:"domain_id"`
	DomainName  string `json:"domain_name"`
	HourlyCount int64  `json:"hourly_count"`
}

// handleAbuseDashboard returns current sending rates per domain and recent
// abuse events for the admin monitoring UI.
func (s *Server) handleAbuseDashboard(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Get all active domains for rate display.
	active := true
	domains, err := s.domains.List(ctx, &active)
	if err != nil {
		s.logger.Error("list domains for abuse dashboard failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load domains")
		return
	}

	// R2: restrict the per-domain rate display to the caller's domain scope —
	// this handler previously emitted rates + names for every active domain
	// regardless of an API key's ScopedDomainIDs (cross-tenant send-rate leak).
	allowedSet, unrestricted := s.domainFilter(ctx)

	var rates []domainRate
	if s.abuseDetector != nil {
		for _, d := range domains {
			if !unrestricted && !allowedSet[d.ID] {
				continue
			}
			count, _ := s.abuseDetector.GetDomainHourlyCount(ctx, d.ID)
			if count > 0 {
				rates = append(rates, domainRate{
					DomainID:    d.ID,
					DomainName:  d.Name,
					HourlyCount: count,
				})
			}
		}
	}
	if rates == nil {
		rates = []domainRate{}
	}

	events, err := s.abuseEvents.ListRecent(ctx, 20)
	if err != nil {
		s.logger.Error("list abuse events for dashboard failed", "error", err)
		events = []repository.AbuseEvent{}
	}
	events = s.filterAbuseEventsByScope(ctx, events)
	if events == nil {
		events = []repository.AbuseEvent{}
	}

	respond(w, r, http.StatusOK, abuseDashboard{
		DomainRates:  rates,
		RecentEvents: events,
	})
}
