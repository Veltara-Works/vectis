package api

import (
	"net/http"
	"path/filepath"
	"time"

	vectistls "github.com/Veltara-Works/vectis/internal/tls"
	"github.com/Veltara-Works/vectis/internal/version"
)

type healthResponse struct {
	Status   string                   `json:"status"`
	Version  string                   `json:"version"`
	Services map[string]serviceHealth `json:"services"`
	TLS      *tlsHealth               `json:"tls,omitempty"`
}

type serviceHealth struct {
	Status     string `json:"status"`
	ResponseMs int64  `json:"response_ms"`
	Error      string `json:"error,omitempty"` // why a probed service is unhealthy
}

type tlsHealth struct {
	Mail *certHealth `json:"mail,omitempty"`
}

type certHealth struct {
	Status   string `json:"status"`
	Subject  string `json:"subject,omitempty"`
	DaysLeft int    `json:"days_left,omitempty"`
}

// dependencyHealth pings the api's own dependencies, Postgres and Valkey;
// these alone decide the overall status. Overridable in tests.
func (s *Server) dependencyHealth(r *http.Request) map[string]serviceHealth {
	if s.pingDeps != nil {
		return s.pingDeps(r.Context())
	}
	services := make(map[string]serviceHealth, 2)

	pgStart := time.Now()
	if err := s.db.Ping(r.Context()); err != nil {
		services["postgres"] = serviceHealth{Status: "unhealthy", ResponseMs: time.Since(pgStart).Milliseconds()}
	} else {
		services["postgres"] = serviceHealth{Status: "healthy", ResponseMs: time.Since(pgStart).Milliseconds()}
	}

	vkStart := time.Now()
	cmd := s.vk.B().Ping().Build()
	if err := s.vk.Do(r.Context(), cmd).Error(); err != nil {
		services["valkey"] = serviceHealth{Status: "unhealthy", ResponseMs: time.Since(vkStart).Milliseconds()}
	} else {
		services["valkey"] = serviceHealth{Status: "healthy", ResponseMs: time.Since(vkStart).Milliseconds()}
	}
	return services
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	services := s.dependencyHealth(r)
	overall := "healthy"
	for _, h := range services {
		if h.Status != "healthy" {
			overall = "degraded"
		}
	}

	// Mail services, probed over the network (#264), only when asked
	// (?probes=1, as the dashboard does): the container healthcheck calls this
	// endpoint every few seconds and shouldn't open mail connections. They
	// add per-service rows but never change the overall status, which the
	// api's own healthcheck reads, so a postfix blip can't mark the api
	// unhealthy.
	if s.serviceProbes != nil && r.URL.Query().Get("probes") == "1" {
		for name, h := range s.serviceProbes.Results(r.Context()) {
			services[name] = h
		}
	}

	// Check mail TLS cert.
	var tlsInfo *tlsHealth
	if s.dkimBasePath != "" {
		certDir := filepath.Join(filepath.Dir(s.dkimBasePath), "certs")
		info, err := vectistls.ReadCertInfo(filepath.Join(certDir, "fullchain.pem"))
		if err == nil {
			ch := &certHealth{Subject: info.Subject, DaysLeft: info.DaysLeft}
			if info.IsExpired {
				ch.Status = "expired"
			} else if info.DaysLeft < 14 {
				ch.Status = "expiring"
			} else {
				ch.Status = "valid"
			}
			tlsInfo = &tlsHealth{Mail: ch}
		}
	}

	status := http.StatusOK
	if overall != "healthy" {
		status = http.StatusServiceUnavailable
	}

	respond(w, r, status, healthResponse{
		Status:   overall,
		Version:  version.Version,
		Services: services,
		TLS:      tlsInfo,
	})
}
