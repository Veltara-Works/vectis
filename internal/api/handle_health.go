package api

import (
	"net/http"
	"path/filepath"
	"time"

	vectistls "github.com/Veltara-Works/vectis/internal/tls"
	"github.com/Veltara-Works/vectis/internal/version"
)

type healthResponse struct {
	Status   string                    `json:"status"`
	Version  string                    `json:"version"`
	Services map[string]serviceHealth  `json:"services"`
	TLS      *tlsHealth               `json:"tls,omitempty"`
}

type serviceHealth struct {
	Status     string `json:"status"`
	ResponseMs int64  `json:"response_ms"`
}

type tlsHealth struct {
	Mail *certHealth `json:"mail,omitempty"`
}

type certHealth struct {
	Status   string `json:"status"`
	Subject  string `json:"subject,omitempty"`
	DaysLeft int    `json:"days_left,omitempty"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	services := make(map[string]serviceHealth)
	overall := "healthy"

	// Check Postgres with timing.
	pgStart := time.Now()
	if err := s.db.Ping(r.Context()); err != nil {
		services["postgres"] = serviceHealth{Status: "unhealthy", ResponseMs: time.Since(pgStart).Milliseconds()}
		overall = "degraded"
	} else {
		services["postgres"] = serviceHealth{Status: "healthy", ResponseMs: time.Since(pgStart).Milliseconds()}
	}

	// Check Valkey with timing.
	vkStart := time.Now()
	cmd := s.vk.B().Ping().Build()
	if err := s.vk.Do(r.Context(), cmd).Error(); err != nil {
		services["valkey"] = serviceHealth{Status: "unhealthy", ResponseMs: time.Since(vkStart).Milliseconds()}
		overall = "degraded"
	} else {
		services["valkey"] = serviceHealth{Status: "healthy", ResponseMs: time.Since(vkStart).Milliseconds()}
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
