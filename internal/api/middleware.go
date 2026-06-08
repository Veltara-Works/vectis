package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/types"
)

type contextKey string

const (
	ctxRequestID contextKey = "request_id"
	ctxAdminID   contextKey = "admin_id"
	ctxSessionID contextKey = "session_id"
	ctxAdminRole contextKey = "admin_role"
	ctxAPIKeyID  contextKey = "api_key_id"
)

func getRequestID(ctx context.Context) string {
	if id, ok := ctx.Value(ctxRequestID).(string); ok {
		return id
	}
	return ""
}

func getAdminID(ctx context.Context) string {
	if id, ok := ctx.Value(ctxAdminID).(string); ok {
		return id
	}
	return ""
}

func getSessionID(ctx context.Context) string {
	if id, ok := ctx.Value(ctxSessionID).(string); ok {
		return id
	}
	return ""
}

func getAdminRole(ctx context.Context) string {
	if role, ok := ctx.Value(ctxAdminRole).(string); ok {
		return role
	}
	return ""
}

func getAPIKeyID(ctx context.Context) string {
	if id, ok := ctx.Value(ctxAPIKeyID).(string); ok {
		return id
	}
	return ""
}

// securityHeaders sets standard HTTP security headers on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		next.ServeHTTP(w, r)
	})
}

// requestIDMiddleware injects a UUIDv7 request ID into each request context.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := types.NewUUIDv7()
		ctx := context.WithValue(r.Context(), ctxRequestID, requestID)
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// jsonContentType sets the Content-Type header to application/json.
func jsonContentType(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		next.ServeHTTP(w, r)
	})
}

// loggingMiddleware logs each request with structured fields per ADR-024.
func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := &responseWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(ww, r)

		duration := time.Since(start)
		attrs := []any{
			"method", r.Method,
			"path", r.URL.Path,
			"status", ww.status,
			"duration_ms", duration.Milliseconds(),
			"request_id", getRequestID(r.Context()),
			"ip", clientIP(r),
			"user_agent", r.UserAgent(),
			"bytes", ww.bytesWritten,
		}

		if adminID := getAdminID(r.Context()); adminID != "" {
			attrs = append(attrs, "admin_id", adminID)
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

// authMiddleware validates authentication via session cookie, HMAC-signed
// Bearer token, or API key (vectis_* prefix).
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signedToken := extractSignedToken(r)
		if signedToken == "" {
			respondError(w, r, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication required")
			return
		}

		// API key auth: tokens starting with "vectis_" are API keys.
		if auth.IsAPIKey(signedToken) {
			s.authenticateAPIKey(w, r, next, signedToken)
			return
		}

		// Session auth: HMAC-signed session token.
		rawToken, err := s.sessions.VerifyAndExtractToken(signedToken)
		if err != nil {
			respondError(w, r, http.StatusUnauthorized, "SESSION_INVALID", "Invalid session token")
			return
		}

		sessionID, adminID, err := s.sessions.ValidateSession(r.Context(), rawToken)
		if err != nil {
			respondError(w, r, http.StatusUnauthorized, "SESSION_INVALID", "Session expired or invalid")
			return
		}

		admin, err := s.admins.GetByID(r.Context(), adminID)
		if err != nil || admin == nil {
			respondError(w, r, http.StatusUnauthorized, "SESSION_INVALID", "Admin account not found")
			return
		}

		ctx := context.WithValue(r.Context(), ctxAdminID, adminID)
		ctx = context.WithValue(ctx, ctxSessionID, sessionID)
		ctx = context.WithValue(ctx, ctxAdminRole, admin.Role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// authenticateAPIKey validates an API key and sets the admin context.
func (s *Server) authenticateAPIKey(w http.ResponseWriter, r *http.Request, next http.Handler, rawKey string) {
	keyHash := auth.HashAPIKey(rawKey)
	apiKey, err := s.apiKeys.GetByHash(r.Context(), keyHash)
	if err != nil {
		s.logger.Error("api key lookup failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error")
		return
	}
	if apiKey == nil {
		respondError(w, r, http.StatusUnauthorized, "API_KEY_INVALID", "Invalid or expired API key")
		return
	}

	// Load admin for RBAC.
	admin, err := s.admins.GetByID(r.Context(), apiKey.AdminID)
	if err != nil || admin == nil {
		respondError(w, r, http.StatusUnauthorized, "API_KEY_INVALID", "API key owner account not found")
		return
	}

	// Enforce the per-key requests/minute budget (api_keys.rate_limit) before
	// any work. Placed ahead of TouchLastUsed so a 429 flood doesn't spam
	// last_used updates. Fail-open on limiter errors.
	if !s.enforceAPIKeyRateLimit(w, r, apiKey) {
		return
	}

	// Touch last_used_at (fire-and-forget).
	go s.apiKeys.TouchLastUsed(context.Background(), apiKey.ID)

	ctx := context.WithValue(r.Context(), ctxAdminID, apiKey.AdminID)
	ctx = context.WithValue(ctx, ctxAdminRole, admin.Role)
	ctx = context.WithValue(ctx, ctxAPIKeyID, apiKey.ID)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// extractSignedToken gets the signed token from the cookie or Authorization header.
func extractSignedToken(r *http.Request) string {
	// Try cookie first.
	if cookie, err := r.Cookie("vectis_session"); err == nil && cookie.Value != "" {
		return cookie.Value
	}

	// Fall back to Bearer token (also expected to be HMAC-signed).
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}

	return ""
}

// requireRole returns middleware that restricts access to the given roles.
func requireRole(roles ...string) func(http.Handler) http.Handler {
	allowed := make(map[string]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := getAdminRole(r.Context())
			if !allowed[role] {
				respondError(w, r, http.StatusForbidden, "FORBIDDEN",
					"You do not have permission to access this resource")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireSuperAdmin is a convenience wrapper for requireRole(auth.RoleSuperAdmin).
func requireSuperAdmin() func(http.Handler) http.Handler {
	return requireRole(auth.RoleSuperAdmin)
}

// requireAdminOrAbove restricts access to admin and super_admin roles.
func requireAdminOrAbove() func(http.Handler) http.Handler {
	return requireRole(auth.RoleSuperAdmin, auth.RoleAdmin)
}

// canAccessDomain checks if the current admin has access to the given domain.
// Returns true for super_admin and admin roles; for domain_admin, checks the junction table.
func (s *Server) canAccessDomain(ctx context.Context, domainID string) bool {
	role := getAdminRole(ctx)
	if auth.CanAccessAllDomains(role) {
		return true
	}
	adminID := getAdminID(ctx)
	ok, err := s.adminDomains.HasAccess(ctx, adminID, domainID)
	if err != nil {
		s.logger.Error("check domain access failed", "error", err, "admin_id", adminID, "domain_id", domainID)
		return false
	}
	return ok
}

// getAllowedDomainIDs returns the domain IDs the current admin can access.
// Returns nil for roles with unrestricted access (meaning "all domains").
func (s *Server) getAllowedDomainIDs(ctx context.Context) []string {
	role := getAdminRole(ctx)
	if auth.CanAccessAllDomains(role) {
		return nil // nil means unrestricted
	}
	ids, err := s.adminDomains.ListDomainIDs(ctx, getAdminID(ctx))
	if err != nil {
		s.logger.Error("list allowed domains failed", "error", err)
		return []string{} // empty = no access
	}
	return ids
}

// clientIP extracts just the IP address from r.RemoteAddr, stripping the port.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// responseWriter wraps http.ResponseWriter to capture status and bytes.
type responseWriter struct {
	http.ResponseWriter
	status       int
	bytesWritten int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	n, err := rw.ResponseWriter.Write(b)
	rw.bytesWritten += n
	return n, err
}
