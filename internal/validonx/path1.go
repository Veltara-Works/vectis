package validonx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// path1.go — interim adapter for the ValidonX path-1 endpoint
// /api/v1/integration/entitlements/check.
//
// Used during v0.1.0-beta1 while the dedicated /v1/licensing/resolve endpoint
// (path-2) is being built on the ValidonX side. The path-1 endpoint exists
// today and returns granted/denied per-feature; it does NOT surface
// subscription Status or grace-period expiry, so this adapter synthesises
// those fields from HTTP response patterns to keep the rest of Vectis
// unchanged (cache, middleware, License admin UI, request flow).
//
// When path-2 ships with /v1/licensing/resolve matching our LicenseResponse
// struct natively, this whole file gets deleted in one commit and
// CheckLicense() reverts to its native shape.
//
// Spec authority: ValidonX team email of 2026-04-25, "Re: Vectis v0.1.0 GA
// — endpoint spec for path 1". Full spec at
// docs/external/integration/entitlements-check-endpoint.md in the ValidonX
// repo.

const (
	// path1EntitlementsPath is the integration endpoint path appended to the
	// configured base URL. Note the doubled /api/v1/ — Laravel route grouping
	// on the ValidonX side mounts routes/api.php under /api/ and we prefix
	// integration routes with v1/integration/. Confirmed mandatory.
	path1EntitlementsPath = "/api/v1/integration/entitlements/check"

	// path1MaxRetryAfter caps how long we'll honour a 429 Retry-After header
	// before giving up. Stops a misbehaving server from blocking the request
	// indefinitely; well past path-1's expected response latency.
	path1MaxRetryAfter = 30 * time.Second

	// path1Status constants — synthesised from HTTP response patterns since
	// the path-1 endpoint doesn't return SubscriptionStatus directly.
	// Path-2's /v1/licensing/resolve returns these natively.
	path1StatusActive    = "active"
	path1StatusSuspended = "suspended"
	path1StatusNotFound  = "not_found"
)

// path1Request is the JSON body shape for /api/v1/integration/entitlements/check.
type path1Request struct {
	LicenseKey string   `json:"license_key"`
	Features   []string `json:"features"`
}

// path1FeatureGrant is the per-feature record under data.entitlements.features.
type path1FeatureGrant struct {
	Granted bool `json:"granted"`
	Value   any  `json:"value,omitempty"`
}

// path1Response mirrors the path-1 endpoint envelope.
//
// The `limits` field is intentionally omitted: ValidonX returns it as an
// empty JSON array (`"limits": []`) when no limits are configured for the
// license, but its populated shape is undocumented as of the v0.1.0-beta1
// integration. We don't use limits data anywhere in synthesiseLicenseResponse
// or downstream, so leaving it out lets json.Unmarshal silently skip the
// field rather than typo-fight ValidonX's shape. When limits become a
// product feature (post-v0.1.x), re-add the field with a type that matches
// a real populated sample.
type path1Response struct {
	Data struct {
		Entitlements struct {
			Features map[string]path1FeatureGrant `json:"features"`
		} `json:"entitlements"`
	} `json:"data"`
	Meta struct {
		RequestID  string `json:"request_id"`
		APIVersion string `json:"api_version"`
	} `json:"meta"`
}

// path1ErrorEnvelope is the standard ValidonX error response.
type path1ErrorEnvelope struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
	Meta struct {
		RequestID string `json:"request_id"`
	} `json:"meta,omitempty"`
}

// CheckLicensePath1 calls the ValidonX path-1 entitlements-check endpoint and
// translates its response into the LicenseResponse shape the rest of Vectis
// expects. Always requests the full known feature set (per ValidonX team
// recommendation 2026-04-25) so the adapter doesn't need to change as more
// gates are wired in v0.1.x.
//
// Synthesis rules for the four LicenseResponse fields:
//
//   - AllowedFeatures: keys from data.entitlements.features where granted=true.
//   - Status: "active" on 200 with at least one core feature granted;
//     "suspended" on 403 TENANT.STATUS.SUSPENDED; "not_found" on 404
//     LICENSE.NOT_FOUND. Empty on other error classes.
//   - Valid: true iff Status == "active". Other statuses set Valid=false so
//     the FeatureGate middleware correctly rejects access.
//   - ExpiresAt: zero. The path-1 endpoint doesn't surface grace-period
//     expiry. Vectis falls back to its own 30-day local cache TTL
//     (validonx.GracePeriod), which is the intended behaviour.
//
// On 429 the adapter honours Retry-After (capped at 30s) and retries once.
// Subsequent 429s surface as errors; the caller decides whether to retry
// (the cache layer's grace period handles transient rate-limit blips).
func (c *Client) CheckLicensePath1(ctx context.Context, requestedFeatures []string) (*LicenseResponse, error) {
	if c == nil || !c.Configured() {
		return nil, fmt.Errorf("validonx client not configured")
	}
	if c.licenseKey == "" {
		return nil, fmt.Errorf("path-1: license_key is empty (set validonx.license_key in secrets.yaml)")
	}

	if len(requestedFeatures) == 0 {
		// Default to the full set we know about, per ValidonX team's
		// recommendation. Future feature constants get appended here
		// without changing the adapter contract.
		requestedFeatures = []string{
			FeatureBasicMail,
			FeatureAnalytics,
			FeatureOIDCSSO,
			FeatureCustomBranding,
			FeatureAdvancedSpam,
			FeaturePrioritySupport,
		}
	}

	body, err := json.Marshal(path1Request{
		LicenseKey: c.licenseKey,
		Features:   requestedFeatures,
	})
	if err != nil {
		return nil, fmt.Errorf("path-1: marshal request: %w", err)
	}

	resp, retryErr := c.path1RoundTrip(ctx, body)
	if retryErr != nil {
		return nil, retryErr
	}
	defer resp.Body.Close()

	respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1 MB max
	if readErr != nil {
		return nil, fmt.Errorf("path-1: read response: %w", readErr)
	}

	switch resp.StatusCode {
	case http.StatusOK:
		var parsed path1Response
		if err := json.Unmarshal(respBody, &parsed); err != nil {
			return nil, fmt.Errorf("path-1: decode 200 response: %w (body: %s)", err, snippet(respBody))
		}
		return synthesiseLicenseResponse(&parsed), nil

	case http.StatusForbidden:
		envelope := decodeErrorEnvelope(respBody)
		c.logger.Warn("path-1: tenant suspended",
			"code", envelope.Error.Code,
			"request_id", envelope.Meta.RequestID,
		)
		// Surface as a "valid: false" LicenseResponse rather than an error
		// so the License admin UI shows the correct tier-revert state
		// instead of a generic activation failure.
		return &LicenseResponse{
			AllowedFeatures: nil,
			Status:          path1StatusSuspended,
			Valid:           false,
		}, nil

	case http.StatusNotFound:
		envelope := decodeErrorEnvelope(respBody)
		c.logger.Warn("path-1: license not found",
			"code", envelope.Error.Code,
			"request_id", envelope.Meta.RequestID,
		)
		return &LicenseResponse{
			AllowedFeatures: nil,
			Status:          path1StatusNotFound,
			Valid:           false,
		}, nil

	case http.StatusUnauthorized:
		envelope := decodeErrorEnvelope(respBody)
		// Auth failures are operator-side configuration bugs, not customer
		// state changes. Surface as an error so the License POST handler
		// returns 422 LICENSE_VALIDATION_FAILED with a meaningful message.
		return nil, fmt.Errorf("path-1: %s: %s", envelope.Error.Code, envelope.Error.Message)

	case http.StatusUnprocessableEntity:
		envelope := decodeErrorEnvelope(respBody)
		return nil, fmt.Errorf("path-1: validation failed: %s: %s",
			envelope.Error.Code, envelope.Error.Message)

	case http.StatusTooManyRequests:
		// Already retried once inside path1RoundTrip; if we're still 429,
		// bubble up as an error and let the cache's grace period absorb it.
		envelope := decodeErrorEnvelope(respBody)
		return nil, fmt.Errorf("path-1: rate limited after retry: %s", envelope.Error.Message)

	default:
		envelope := decodeErrorEnvelope(respBody)
		return nil, fmt.Errorf("path-1: HTTP %d %s: %s",
			resp.StatusCode, envelope.Error.Code, envelope.Error.Message)
	}
}

// path1RoundTrip performs the single POST with X-API-Key + X-Request-ID
// headers, honouring one Retry-After-bounded retry on 429.
func (c *Client) path1RoundTrip(ctx context.Context, body []byte) (*http.Response, error) {
	for attempt := 0; attempt < 2; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			c.baseURL+path1EntitlementsPath, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("path-1: build request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json")
		req.Header.Set("X-API-Key", c.serviceKey)
		// Echo a request ID so traces pair up cleanly across the two systems.
		req.Header.Set("X-Request-ID", newRequestID())

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("path-1: validonx unreachable: %w", err)
		}

		if resp.StatusCode != http.StatusTooManyRequests || attempt > 0 {
			return resp, nil
		}

		// 429 — honour Retry-After with cap, then retry once.
		retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
		_ = resp.Body.Close()
		if retryAfter > path1MaxRetryAfter {
			retryAfter = path1MaxRetryAfter
		}
		if retryAfter <= 0 {
			retryAfter = 1 * time.Second
		}
		c.logger.Info("path-1: rate limited, retrying",
			"retry_after", retryAfter, "attempt", attempt+1)

		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(retryAfter):
			continue
		}
	}
	return nil, errors.New("path-1: exhausted retries")
}

// synthesiseLicenseResponse converts a parsed path-1 response into the
// LicenseResponse shape the rest of Vectis expects. Pure function — no IO,
// no client state — so the synthesis logic is straightforward to unit-test.
func synthesiseLicenseResponse(parsed *path1Response) *LicenseResponse {
	allowed := make([]string, 0, len(parsed.Data.Entitlements.Features))
	hasCore := false
	for name, grant := range parsed.Data.Entitlements.Features {
		if !grant.Granted {
			continue
		}
		allowed = append(allowed, name)
		if name != FeatureBasicMail {
			// Any granted non-basic feature counts toward "core present" —
			// FeatureBasicMail alone is just Free tier and shouldn't flip
			// Valid=true via path-1 (Free customers don't have license_keys
			// so they don't reach here in the first place, but defensive).
			hasCore = true
		}
	}

	status := path1StatusActive
	valid := hasCore
	if !valid {
		// 200 OK but no core features granted — treat as inactive so the
		// gate middleware rejects access. ValidonX may return this if the
		// license key resolves but its entitlements JSON is empty (mid-
		// rollout config drift).
		status = ""
	}

	return &LicenseResponse{
		AllowedFeatures: allowed,
		Status:          status,
		Valid:           valid,
	}
}

// decodeErrorEnvelope extracts a path1ErrorEnvelope from the response body,
// returning a zero-value envelope on parse failure (so callers can still
// log a meaningful HTTP status without a nil deref).
func decodeErrorEnvelope(body []byte) path1ErrorEnvelope {
	var env path1ErrorEnvelope
	_ = json.Unmarshal(body, &env)
	return env
}

// parseRetryAfter accepts either delta-seconds (RFC 7231 §7.1.3) or an HTTP
// date and returns a duration. Returns 0 on parse failure or past-dated.
func parseRetryAfter(raw string) time.Duration {
	if raw == "" {
		return 0
	}
	if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(raw); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}

// snippet trims a body to a length safe for log lines.
func snippet(body []byte) string {
	const limit = 256
	if len(body) <= limit {
		return string(body)
	}
	return string(body[:limit]) + "...(truncated)"
}

// newRequestID generates a short trace identifier. Crypto-quality not
// required here — this is a request-correlation hint, not a session token.
func newRequestID() string {
	return fmt.Sprintf("vec-%d", time.Now().UnixNano())
}
