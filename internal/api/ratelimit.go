package api

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/Veltara-Works/vectis/internal/ratelimit"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// apiKeyRateLimitWindow is the budget period for the per-key requests/minute
// limit stored in api_keys.rate_limit.
const apiKeyRateLimitWindow = time.Minute

func apiKeyRateLimitKey(apiKeyID string) string {
	return "ratelimit:apikey:" + apiKeyID
}

// enforceAPIKeyRateLimit applies the per-key requests-per-minute budget stored
// in api_keys.rate_limit (0 = unlimited). It is fail-OPEN: any Valkey error is
// logged and the request is allowed, so a limiter outage never becomes an API
// outage. Returns true if the request may proceed; on rejection it has already
// written the 429 response (with Retry-After + X-RateLimit-* headers).
func (s *Server) enforceAPIKeyRateLimit(w http.ResponseWriter, r *http.Request, apiKey *repository.APIKey) bool {
	if apiKey.RateLimit <= 0 {
		return true // unlimited — no budget, so no rate-limit headers
	}
	key := apiKeyRateLimitKey(apiKey.ID)

	// Advertise the configured ceiling on every budgeted-key response, including
	// the fail-open path below where we can't compute the remaining count — so a
	// budgeted key always carries at least X-RateLimit-Limit.
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(apiKey.RateLimit))

	res, err := ratelimit.Allow(r.Context(), s.vk, key, apiKey.RateLimit, apiKeyRateLimitWindow)
	if err != nil {
		s.logger.Warn("api key rate limit check failed; allowing (fail-open)", "error", err, "api_key_id", apiKey.ID)
		return true
	}

	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(res.Remaining))

	if !res.Allowed {
		// RetryAfter is floored at 1s, so Retry-After and X-RateLimit-Reset
		// (both derived from the same duration) always agree.
		retry := ratelimit.RetryAfter(r.Context(), s.vk, key, apiKeyRateLimitWindow)
		secs := int(retry.Seconds())
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(retry).Unix(), 10))
		respondError(w, r, http.StatusTooManyRequests, "API_KEY_RATE_LIMITED",
			fmt.Sprintf("API key rate limit exceeded: %d requests per minute. Retry after %d seconds.", res.Limit, secs))
		return false
	}
	return true
}
