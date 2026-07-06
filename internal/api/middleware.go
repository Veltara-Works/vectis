package api

import (
	"context"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/types"
	"github.com/go-chi/chi/v5"
)

type contextKey string

const (
	ctxRequestID contextKey = "request_id"
	ctxAdminID   contextKey = "admin_id"
	ctxSessionID contextKey = "session_id"
	ctxAdminRole contextKey = "admin_role"
	ctxAPIKeyID  contextKey = "api_key_id"
	// ctxAPIKeyScope holds the authenticating API key's ScopedDomainIDs, stashed
	// at auth time (the key is already loaded via GetByHash) so domain-scope
	// checks read it from context instead of re-querying api_keys on every
	// canAccessDomain call. Absent for session auth; an empty slice means an
	// unscoped key ("all domains").
	ctxAPIKeyScope contextKey = "api_key_scope"
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

// getAPIKeyScope returns the authenticating API key's ScopedDomainIDs and whether
// the request was API-key authenticated at all. isKey is false for session auth.
// For an unscoped key isKey is true with an empty (or nil) scope.
func getAPIKeyScope(ctx context.Context) (scope []string, isKey bool) {
	v := ctx.Value(ctxAPIKeyScope)
	if v == nil {
		return nil, false
	}
	scope, _ = v.([]string)
	return scope, true
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
	// Stash the key's domain scope now (already loaded, active/expiry-validated
	// by GetByHash) so domain-scope checks don't re-query per request.
	ctx = context.WithValue(ctx, ctxAPIKeyScope, apiKey.ScopedDomainIDs)
	next.ServeHTTP(w, r.WithContext(ctx))
}

// csrfProtect guards cookie-authenticated, state-changing requests against
// cross-site request forgery. The session cookie is SameSite=Strict (the
// primary defence — the browser won't attach it to cross-site requests at all);
// this adds a stateless Origin/Referer check as defence in depth (#127).
//
// It acts ONLY when the browser auto-attached a session cookie on an unsafe
// method. Bearer/API-key clients send no session cookie and carry no ambient
// authority, so they're skipped (CLI/integrations have no Origin and must keep
// working). The unauthenticated login / SAML-ACS / OIDC-callback routes live
// outside this group, so IdP-initiated cross-origin POSTs are unaffected. The
// admin UI is same-origin with the API, so legitimate requests always pass with
// no frontend change.
func (s *Server) csrfProtect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isSafeMethod(r.Method) {
			next.ServeHTTP(w, r)
			return
		}
		if c, err := r.Cookie(sessionCookieName); err != nil || c.Value == "" {
			next.ServeHTTP(w, r) // no session cookie → not CSRF-able
			return
		}
		if !s.originAllowed(r) {
			respondError(w, r, http.StatusForbidden, "CSRF_FAILED",
				"Cross-origin state-changing request rejected")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// isSafeMethod reports whether the HTTP method is read-only (RFC 7231 §4.2.1)
// and therefore not a CSRF concern.
func isSafeMethod(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// originAllowed reports whether a state-changing request targets this server's
// own host. The browser sets Origin from the page issuing the request and won't
// let a cross-site page forge it, while Host is the host the request was
// actually sent to — so an evil.example page hitting us carries
// Origin: https://evil.example against Host: mail.example and is rejected.
//
// It verifies Origin/Referer only when at least one is present. With neither, it
// defers to the SameSite=Strict cookie (the primary defence) rather than failing
// closed — some legitimate setups (older browsers, privacy proxies) strip both,
// and an attacker cannot suppress Origin on their own cross-origin request, so
// deferring opens no hole. A present-but-non-matching or opaque ("null") Origin
// is still rejected.
func (s *Server) originAllowed(r *http.Request) bool {
	if r.Header.Get("Origin") == "" && r.Header.Get("Referer") == "" {
		return true // no signal; rely on SameSite=Strict
	}
	got := requestOriginHost(r)
	if got == "" {
		return false // header present but opaque/unparseable → not same-origin
	}
	if strings.EqualFold(got, hostWithoutPort(r.Host)) {
		return true
	}
	// Also accept the configured public hostname, in case a reverse proxy
	// presents a different Host to the backend than the browser addressed.
	if s.cfg != nil && s.cfg.Hostname != "" && strings.EqualFold(got, hostWithoutPort(s.cfg.Hostname)) {
		return true
	}
	return false
}

// requestOriginHost returns the host of the request's Origin header, falling
// back to the Referer host. Empty if neither is present or parseable (incl. the
// "null" origin, which has no host).
func requestOriginHost(r *http.Request) string {
	if o := r.Header.Get("Origin"); o != "" {
		if u, err := url.Parse(o); err == nil {
			return hostWithoutPort(u.Host)
		}
		return ""
	}
	if ref := r.Header.Get("Referer"); ref != "" {
		if u, err := url.Parse(ref); err == nil {
			return hostWithoutPort(u.Host)
		}
	}
	return ""
}

// hostWithoutPort returns the host from a host[:port] value. For a host:port it
// returns the bare host (an IPv6 literal comes back unbracketed, e.g.
// "[::1]:443" -> "::1"); for a value with no port it is returned unchanged.
func hostWithoutPort(h string) string {
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

// extractSignedToken gets the signed token from the cookie or Authorization header.
func extractSignedToken(r *http.Request) string {
	// Try cookie first.
	if cookie, err := r.Cookie(sessionCookieName); err == nil && cookie.Value != "" {
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

// requireDomainAccess is the structural choke point for the /domains/{domainID}
// route subtree. It resolves the URL's {domainID} and enforces canAccessDomain
// (API-key scope + domain_admin junction) BEFORE any sub-handler runs, so every
// current and future /domains/{domainID}/... route inherits scope enforcement
// rather than relying on each handler to remember to call canAccessDomain. This
// is the R1 fix for the #119 API-key-scope class: a domain-scoped key (or a
// domain_admin) can no longer reach another domain by hitting a handler that
// only did an RBAC role check. A missing/empty {domainID} fails closed.
func (s *Server) requireDomainAccess(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		domainID := chi.URLParam(r, "domainID")
		if domainID == "" {
			respondError(w, r, http.StatusForbidden, "FORBIDDEN",
				"You do not have permission to access this domain")
			return
		}
		if !s.canAccessDomain(r.Context(), domainID) {
			respondError(w, r, http.StatusForbidden, "FORBIDDEN",
				"You do not have permission to access this domain")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// canAccessDomain checks if the current admin has access to the given domain.
// Returns true for super_admin and admin roles; for domain_admin, checks the junction table.
func (s *Server) canAccessDomain(ctx context.Context, domainID string) bool {
	// API-key domain scoping applies regardless of the underlying admin's role:
	// a scoped key may only touch its listed domains. Enforced here (the single
	// gate every domain-scoped handler calls) so the restriction can't be
	// bypassed by endpoints that previously only checked RBAC.
	if !s.apiKeyAllowsDomain(ctx, domainID) {
		return false
	}
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

// apiKeyAllowsDomain reports whether the request's API key (if any) is permitted
// to act on domainID. Requests authenticated by a session (no API key) or by an
// unscoped API key (empty ScopedDomainIDs) are unrestricted here; a scoped key
// may act only on its listed domains. The key's scope is read from the request
// context (stashed at auth time), so this makes no DB call.
func (s *Server) apiKeyAllowsDomain(ctx context.Context, domainID string) bool {
	scope, isKey := getAPIKeyScope(ctx)
	if !isKey {
		return true // session-authenticated, not an API key
	}
	return domainInScope(scope, domainID)
}

// domainInScope reports whether domainID is permitted by an API key's
// ScopedDomainIDs. An empty scope list means "all domains" (unscoped key).
func domainInScope(scoped []string, domainID string) bool {
	if len(scoped) == 0 {
		return true
	}
	for _, did := range scoped {
		if did == domainID {
			return true
		}
	}
	return false
}

// getAllowedDomainIDs returns the domain IDs the current principal can access,
// or nil for unrestricted ("all domains"). The result is the intersection of the
// admin's role scope AND — for API-key principals — the key's ScopedDomainIDs, so
// a scoped key hitting an all-domains (no domain_id) path can never widen back to
// its owner's role scope. This is the R3 fix for the #119 API-key-scope class
// (Root B). Callers MUST treat a non-nil empty slice as "no access" and filter
// their query by the returned IDs.
// resolveRoleScope normalizes a principal's per-role domain scope. nil is the
// codebase-wide sentinel for "unrestricted / all domains" and MUST only be
// produced for roles that legitimately access every domain. A domain-scoped
// role (domain_admin) with zero assigned domains has NO access, so its scope is
// a non-nil EMPTY slice — never nil. Without this, ListDomainIDs returning nil
// (a domain_admin whose last domain was removed, incl. via the admin_domains
// ON DELETE CASCADE when a domain is deleted) would fall through to nil and
// silently read as "all domains" — a fail-open cross-tenant read (ISO-1).
func resolveRoleScope(canAccessAllDomains bool, assigned []string) []string {
	if canAccessAllDomains {
		return nil // unrestricted — the only legitimate source of the nil sentinel
	}
	if assigned == nil {
		return []string{} // zero assigned domains = no access, never "all domains"
	}
	return assigned
}

func (s *Server) getAllowedDomainIDs(ctx context.Context) []string {
	// Role scope: nil = unrestricted (super_admin/admin), else the domain_admin
	// junction list.
	var roleIDs []string
	role := getAdminRole(ctx)
	if auth.CanAccessAllDomains(role) {
		roleIDs = resolveRoleScope(true, nil)
	} else {
		ids, err := s.adminDomains.ListDomainIDs(ctx, getAdminID(ctx))
		if err != nil {
			s.logger.Error("list allowed domains failed", "error", err)
			return []string{} // empty = no access
		}
		roleIDs = resolveRoleScope(false, ids)
	}

	// API-key scope clamp: a scoped key restricts the principal regardless of the
	// owner's role. Session auth and unscoped keys leave the role scope unchanged.
	// Scope is read from context (stashed at auth time) — no DB round-trip.
	keyScope, isKey := getAPIKeyScope(ctx)
	if !isKey || len(keyScope) == 0 {
		return roleIDs
	}
	if roleIDs == nil {
		return keyScope // role unrestricted → the key scope is the allow-list
	}
	return intersectDomainIDs(roleIDs, keyScope)
}

// intersectDomainIDs returns the elements present in both a and b (set
// intersection). Always returns a non-nil slice so the result reads as an
// explicit allow-list ("no access" when empty), never as nil ("all domains").
func intersectDomainIDs(a, b []string) []string {
	set := make(map[string]bool, len(b))
	for _, x := range b {
		set[x] = true
	}
	out := make([]string, 0, len(a))
	for _, x := range a {
		if set[x] {
			out = append(out, x)
		}
	}
	return out
}

// domainFilter returns the set of domain IDs the caller may see and whether the
// caller is unrestricted ("all domains"). Built from getAllowedDomainIDs: a nil
// result means unrestricted; otherwise the returned set (possibly empty = no
// access) is the explicit allow-list. Used by aggregate/list handlers (abuse,
// webhooks) to drop rows outside the caller's domain scope — the R2 fix for the
// Root-A/B leaks where a scoped key hit an unscoped listing path.
func (s *Server) domainFilter(ctx context.Context) (set map[string]bool, unrestricted bool) {
	ids := s.getAllowedDomainIDs(ctx)
	if ids == nil {
		return nil, true
	}
	set = make(map[string]bool, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set, false
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
