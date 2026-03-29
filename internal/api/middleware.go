package api

import (
	"context"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/types"
)

type contextKey string

const (
	ctxRequestID contextKey = "request_id"
	ctxAdminID   contextKey = "admin_id"
	ctxSessionID contextKey = "session_id"
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

// authMiddleware validates the HMAC-signed session cookie or Authorization header.
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		signedToken := extractSignedToken(r)
		if signedToken == "" {
			respondError(w, r, http.StatusUnauthorized, "AUTH_REQUIRED", "Authentication required")
			return
		}

		// Verify HMAC signature and extract raw token.
		rawToken, err := s.sessions.VerifyAndExtractToken(signedToken)
		if err != nil {
			respondError(w, r, http.StatusUnauthorized, "SESSION_INVALID", "Invalid session token")
			return
		}

		// Validate session by hashing token and looking up in Valkey.
		sessionID, adminID, err := s.sessions.ValidateSession(r.Context(), rawToken)
		if err != nil {
			respondError(w, r, http.StatusUnauthorized, "SESSION_INVALID", "Session expired or invalid")
			return
		}

		ctx := context.WithValue(r.Context(), ctxAdminID, adminID)
		ctx = context.WithValue(ctx, ctxSessionID, sessionID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
