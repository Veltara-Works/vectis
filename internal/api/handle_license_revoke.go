package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/ratelimit"
)

// licenseRevokeMaxBody caps the revoke webhook body. The payload is a tiny JSON
// signal (event type, optional jti for the Phase-2 denylist); anything larger
// is rejected before the HMAC is computed so a hostile caller can't stream an
// unbounded body at us.
const licenseRevokeMaxBody = 64 << 10

// Revoke-webhook rate limit: 10 requests/minute. The JWKS refresh it triggers
// is coalesced, so this is a safety valve against a misbehaving (but
// authenticated) sender, not a correctness requirement.
const (
	licenseRevokeRateLimit  = 10
	licenseRevokeRateWindow = time.Minute
	licenseRevokeRateKey    = "ratelimit:license-revoke"
)

// handleLicenseRevoke is the ValidonX-facing license revoke webhook
// (POST /api/v1/admin/license/revoke). It is authenticated by an HMAC-SHA256
// signature over the raw request body (header `X-Vectis-Signature: sha256=<hex>`)
// keyed by [license].webhook_secret — NOT by an admin session, since the caller
// is ValidonX, not a browser.
//
// On a valid signature it triggers an out-of-band JWKS refresh
// (Refresher.Trigger) so a rotated/revoked signing key is picked up promptly
// instead of waiting for the 12h background cycle. The body is not otherwise
// consumed yet — the jti denylist is a Phase-2 hook.
//
// It is deliberately probe-resistant: when the offline verifier is not
// configured (no refresher) or no webhook_secret is set, it returns the same
// 401 as a bad signature, so an unauthenticated caller cannot distinguish "not
// configured" from "wrong key". Handler order follows the licensing plan:
// configured-check → signature header → HMAC verify → rate-limit → trigger.
func (s *Server) handleLicenseRevoke(w http.ResponseWriter, r *http.Request) {
	// Probe-resistant: one opaque 401 for every authentication failure.
	unauthorized := func() {
		respondError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "invalid or missing signature")
	}

	secret := ""
	if s.secrets != nil && s.secrets.License != nil {
		secret = s.secrets.License.WebhookSecret
	}
	// No refresher means no offline verifier is configured: nothing to revoke,
	// and Trigger would be a nil dereference. Treat as unauthenticated.
	if s.licenseRefresher == nil || secret == "" {
		unauthorized()
		return
	}

	// Read the raw body (capped) — needed verbatim for the HMAC.
	body, err := io.ReadAll(io.LimitReader(r.Body, licenseRevokeMaxBody+1))
	if err != nil || len(body) > licenseRevokeMaxBody {
		unauthorized()
		return
	}

	if !verifyRevokeSignature(secret, body, r.Header.Get("X-Vectis-Signature")) {
		unauthorized()
		return
	}

	// Authenticated. Rate-limit the trigger; fail-open on a limiter outage so a
	// Valkey blip never blocks a legitimate revoke.
	res, err := ratelimit.Allow(r.Context(), s.vk, licenseRevokeRateKey, licenseRevokeRateLimit, licenseRevokeRateWindow)
	if err != nil {
		s.logger.Warn("license revoke rate-limit check failed; allowing (fail-open)", "error", err)
	} else if !res.Allowed {
		retry := ratelimit.RetryAfter(r.Context(), s.vk, licenseRevokeRateKey, licenseRevokeRateWindow)
		w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
		respondError(w, r, http.StatusTooManyRequests, "RATE_LIMITED",
			"license revoke rate limit exceeded")
		return
	}

	s.licenseRefresher.Trigger()
	s.logger.Info("license revoke webhook accepted; triggered jwks refresh")
	respond(w, r, http.StatusAccepted, map[string]string{"status": "refresh_triggered"})
}

// verifyRevokeSignature reports whether header carries a valid "sha256=<hex>"
// HMAC-SHA256 of body keyed by secret. An empty secret always fails (probe
// resistance: an unconfigured webhook behaves identically to a wrong key). The
// comparison is constant-time.
func verifyRevokeSignature(secret string, body []byte, header string) bool {
	if secret == "" {
		return false
	}
	provided, ok := parseSHA256Signature(header)
	if !ok {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return hmac.Equal(provided, mac.Sum(nil))
}

// parseSHA256Signature parses a "sha256=<hex>" signature header into the raw MAC
// bytes. Returns ok=false for a missing header, wrong scheme, non-hex digest, or
// a digest that is not exactly SHA-256 sized. The "sha256=" scheme prefix
// matches the GitHub-style convention used across the portfolio.
func parseSHA256Signature(h string) ([]byte, bool) {
	const prefix = "sha256="
	if !strings.HasPrefix(h, prefix) {
		return nil, false
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(h, prefix))
	if err != nil || len(raw) != sha256.Size {
		return nil, false
	}
	return raw, true
}
