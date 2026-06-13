package orchestrator

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"

	"github.com/Veltara-Works/vectis/internal/engine"
)

// Server is the orchestrator's internal HTTP API server.
type Server struct {
	orch       *Orchestrator
	httpServer *http.Server
	token      string      // bearer token for authentication (fallback when mTLS not configured)
	tlsConfig  *tls.Config // when set, server uses mTLS and bearer token auth is bypassed
	logger     *slog.Logger
}

// ServerConfig holds configuration for the orchestrator HTTP server.
type ServerConfig struct {
	ListenAddr string
	Token      string
	TLSConfig  *tls.Config // optional: enables mTLS when set
}

// NewServer creates a new orchestrator HTTP server with all routes registered.
func NewServer(orch *Orchestrator, cfg ServerConfig, logger *slog.Logger) *Server {
	s := &Server{
		orch:      orch,
		token:     cfg.Token,
		tlsConfig: cfg.TLSConfig,
		logger:    logger,
	}

	router := s.buildRouter()
	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		TLSConfig:    cfg.TLSConfig,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Start begins listening for HTTP requests. Uses TLS when configured.
func (s *Server) Start() error {
	if s.tlsConfig != nil {
		s.logger.Info("starting orchestrator HTTPS server (mTLS)", "addr", s.httpServer.Addr)
		// Certs are already in TLSConfig; pass empty strings to use them.
		if err := s.httpServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
			return fmt.Errorf("orchestrator listen (mTLS): %w", err)
		}
		return nil
	}
	s.logger.Info("starting orchestrator HTTP server", "addr", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("orchestrator listen: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down orchestrator HTTP server")
	return s.httpServer.Shutdown(ctx)
}

// buildRouter creates the chi router with all internal endpoints.
func (s *Server) buildRouter() chi.Router {
	r := chi.NewRouter()

	// Global middleware.
	r.Use(chimw.RealIP)
	r.Use(s.loggingMiddleware)
	r.Use(chimw.Recoverer)

	r.Route("/internal", func(r chi.Router) {
		// Health endpoint is unauthenticated (used by Docker HEALTHCHECK).
		r.Get("/health", s.handleHealth)

		// All other endpoints require bearer token.
		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)
			r.Use(jsonContentType)
			r.Post("/plan", s.handlePlan)
			r.Post("/apply", s.handleApply)
			r.Post("/rollback", s.handleRollback)
			r.Post("/reload", s.handleReload)
			r.Get("/status", s.handleStatus)
		})
	})

	return r
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

// authMiddleware validates the request. With mTLS the client cert has already
// been verified at the TLS layer; without mTLS, the bearer token is checked.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// When mTLS is active, the TLS handshake already verified the client
		// certificate against the CA — no bearer token needed.
		if s.tlsConfig != nil && r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			next.ServeHTTP(w, r)
			return
		}

		// Fallback: bearer token auth.
		auth := r.Header.Get("Authorization")
		if auth == "" {
			s.respondError(w, http.StatusUnauthorized, "AUTH_REQUIRED", "Authorization header required")
			return
		}

		if !strings.HasPrefix(auth, "Bearer ") {
			s.respondError(w, http.StatusUnauthorized, "AUTH_INVALID", "Bearer token required")
			return
		}

		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.token)) != 1 {
			s.respondError(w, http.StatusUnauthorized, "AUTH_INVALID", "Invalid bearer token")
			return
		}

		next.ServeHTTP(w, r)
	})
}

// jsonContentType sets Content-Type to application/json for all responses.
func jsonContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs each request with structured fields.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(ww, r)

		duration := time.Since(start)
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.status,
			"duration_ms", duration.Milliseconds(),
			"ip", clientIP(r),
		}

		if ww.status >= 500 {
			s.logger.Error("http request", attrs...)
		} else if ww.status >= 400 {
			s.logger.Warn("http request", attrs...)
		} else {
			s.logger.Info("http request", attrs...)
		}
	})
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

// handleHealth returns the health status. Unauthenticated for Docker HEALTHCHECK.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	state := s.orch.State()
	healthy := state != StateFailed

	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"healthy": healthy,
		"state":   state,
	}); err != nil {
		s.logger.Error("failed to encode health response", "error", err)
	}
}

// handlePlan triggers a synchronous Plan() computation and returns the result.
func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	plan, err := s.orch.Plan(r.Context())
	if err != nil {
		if _, ok := err.(*ErrInvalidTransition); ok {
			s.respondError(w, http.StatusConflict, "STATE_CONFLICT", err.Error())
			return
		}
		s.respondError(w, http.StatusInternalServerError, "PLAN_FAILED", err.Error())
		return
	}

	s.respondJSON(w, http.StatusOK, map[string]any{
		"state": s.orch.State(),
		"data": map[string]any{
			"plan": plan,
		},
	})
}

// handleApply starts an async Apply() operation and returns the job ID immediately.
func (s *Server) handleApply(w http.ResponseWriter, r *http.Request) {
	state := s.orch.State()
	if !state.CanApply() {
		s.respondError(w, http.StatusConflict, "STATE_CONFLICT",
			fmt.Sprintf("operation %q not allowed in state %q", "apply", state))
		return
	}

	if s.orch.CurrentPlan() == nil {
		s.respondError(w, http.StatusBadRequest, "NO_PLAN", "No plan available; run POST /internal/plan first")
		return
	}

	// Start apply in a goroutine — return the actual job ID immediately.
	// Pre-generate the job ID here so the response matches what Apply() uses.
	jobID := uuid.Must(uuid.NewV7()).String()

	go func() {
		ctx := context.Background()
		returnedID, err := s.orch.ApplyWithJobID(ctx, jobID)
		if err != nil {
			s.logger.Error("apply failed", "job_id", returnedID, "error", err)
		}
	}()

	s.respondJSON(w, http.StatusAccepted, map[string]any{
		"state": StateValidating,
		"data": map[string]any{
			"job_id": jobID,
		},
	})
}

// handleRollback starts an async Rollback() operation and returns the job ID immediately.
func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	state := s.orch.State()
	if !state.CanRollback() {
		s.respondError(w, http.StatusConflict, "STATE_CONFLICT",
			fmt.Sprintf("operation %q not allowed in state %q", "rollback", state))
		return
	}

	jobID := uuid.Must(uuid.NewV7()).String()

	// Start rollback in a goroutine — return the actual job ID immediately.
	go func() {
		ctx := context.Background()
		returnedID, err := s.orch.RollbackWithJobID(ctx, jobID)
		if err != nil {
			s.logger.Error("rollback failed", "job_id", returnedID, "error", err)
		}
	}()

	s.respondJSON(w, http.StatusAccepted, map[string]any{
		"state": StateRollingBack,
		"data": map[string]any{
			"job_id": jobID,
		},
	})
}

// handleReload runs best-effort service reload/restart actions on behalf of
// callers that lack docker access — notably the api container, which has no
// docker socket of its own (only the orchestrator mounts /var/run/docker.sock).
// Reload is independent of the apply state machine: it is a lightweight signal
// (e.g. SIGHUP to rspamd) and is safe to run in any state.
func (s *Server) handleReload(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Actions []engine.ServiceAction `json:"actions"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid reload request body")
		return
	}

	results := engine.ExecuteActions(req.Actions)
	s.respondJSON(w, http.StatusOK, map[string]any{
		"state": s.orch.State(),
		"data": map[string]any{
			"results": results,
		},
	})
}

// handleStatus returns the current state and last operation details.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	state := s.orch.State()
	lastOp := s.orch.LastOperation()

	data := map[string]any{
		"state": state,
	}
	if lastOp != nil {
		data["data"] = map[string]any{
			"last_operation": lastOp,
		}
	}

	// Surface the in-flight orchestrator self-replace window (rc36) so the UI
	// can render a countdown banner during the ~30s helper-delay after Apply
	// otherwise completes. Nil when no self-replacement is pending — most of
	// the time this is a no-op Valkey GET.
	if until := s.orch.SelfUpgradeUntil(r.Context()); until != nil {
		data["self_upgrade_until"] = until.UTC().Format(time.RFC3339)
	}

	s.respondJSON(w, http.StatusOK, data)
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

func (s *Server) respondJSON(w http.ResponseWriter, status int, payload any) {
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		s.logger.Error("failed to encode response", "error", err)
	}
}

func (s *Server) respondError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	}); err != nil {
		s.logger.Error("failed to encode error response", "error", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// statusWriter wraps http.ResponseWriter to capture the status code.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// clientIP extracts the IP from r.RemoteAddr, stripping the port.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
