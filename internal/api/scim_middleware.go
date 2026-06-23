package api

import (
	"context"
	"log/slog"
	"net/http"
	"strings"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/Veltara-Works/vectis/internal/scim"
	"github.com/Veltara-Works/vectis/internal/validonx"
)

// scimFeatureGate denies non-Enterprise installs with a SCIM-shaped 403. It
// reuses the entitlement logic via featureGate.HasFeature (which returns false
// for every deny path — unconfigured/Free, Pro-without-scim, lapsed Enterprise
// past the offline horizon), keeping the SCIM error shape isolated from the
// Vectis envelope that writeFeatureError emits.
func (s *Server) scimFeatureGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.featureGate.HasFeature(r.Context(), validonx.FeatureSCIM) {
			scim.WriteError(w, http.StatusForbidden, "",
				"SCIM provisioning requires a Vectis Enterprise license.")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ctxSCIMTokenID carries the authenticated SCIM token id for downstream
// audit / last-used use.
const ctxSCIMTokenID contextKey = "scim_token_id"

// scimTokenStore is the subset of repository.SCIMTokenRepo the auth middleware
// depends on. Declared as an interface so the middleware is unit-testable
// without a database. *repository.SCIMTokenRepo satisfies it.
type scimTokenStore interface {
	GetByHash(ctx context.Context, tokenHash string) (*repository.SCIMToken, error)
	TouchLastUsed(ctx context.Context, id string)
}

// scimAuthMiddleware returns chi middleware that authenticates SCIM requests via
// a static "Authorization: Bearer scim_…" token (machine-to-machine — not a
// session, and deliberately separate from the admin authMiddleware so a SCIM
// token can never impersonate an admin role). On any failure it returns a
// SCIM-shaped 401 (never the Vectis envelope). On success the authenticated
// token id is placed on the request context.
func scimAuthMiddleware(tokens scimTokenStore, logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw := scimBearerToken(r)
			if raw == "" || !auth.IsSCIMToken(raw) {
				scim.WriteError(w, http.StatusUnauthorized, "", "Missing or malformed SCIM bearer token")
				return
			}

			tok, err := tokens.GetByHash(r.Context(), auth.HashAPIKey(raw))
			if err != nil {
				logger.Error("scim token lookup failed", "error", err)
				scim.WriteError(w, http.StatusInternalServerError, "", "Internal error")
				return
			}
			if tok == nil {
				// Covers unknown / revoked / expired — GetByHash filters those out.
				scim.WriteError(w, http.StatusUnauthorized, "", "Invalid, expired, or revoked SCIM token")
				return
			}

			// Stamp last_used_at without blocking the request.
			go tokens.TouchLastUsed(context.Background(), tok.ID)

			ctx := context.WithValue(r.Context(), ctxSCIMTokenID, tok.ID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// scimBearerToken extracts the raw value of an "Authorization: Bearer <token>"
// header, or "" if absent. The auth scheme name is matched case-insensitively
// (RFC 7235 §2.1 — scheme names are case-insensitive) so a client sending
// "bearer"/"BEARER" is not spuriously rejected. SCIM clients never present a
// cookie.
func scimBearerToken(r *http.Request) string {
	scheme, token, found := strings.Cut(r.Header.Get("Authorization"), " ")
	if !found || !strings.EqualFold(scheme, "Bearer") {
		return ""
	}
	return strings.TrimSpace(token)
}
