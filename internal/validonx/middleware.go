package validonx

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

var errClientNotConfigured = errors.New("validonx client not configured")

// ---------------------------------------------------------------------------
// Feature tiers — defines which features belong to each license tier
// ---------------------------------------------------------------------------

const (
	TierFree       = "free"
	TierPro        = "pro"
	TierEnterprise = "enterprise"
)

// Feature constants for use with FeatureGate middleware.
const (
	FeatureBasicMail       = "basic_mail"              // domains, mailboxes, aliases
	FeatureAnalytics       = "analytics"               // Pro: per-domain analytics dashboard
	FeatureOIDCSSO         = "oidc_sso"                // Pro: OIDC single sign-on
	FeatureCustomBranding  = "custom_branding"         // Pro: custom branding
	FeatureAdvancedSpam    = "advanced_spam"           // Pro: advanced spam config
	FeaturePrioritySupport = "priority_support"        // Pro: priority support
	FeatureSAMLSSO         = "saml_sso"                // Enterprise: SAML 2.0 single sign-on
	// NOTE: multi_tenant (tenant isolation) is intentionally omitted. It is
	// unbuilt and belongs to the future Vectis Cloud managed-platform tier, not
	// self-host Enterprise. Re-introduce the constant + tier mapping if/when
	// Vectis Cloud ships it. See project_vectis_cloud_concept.
	FeatureDeliverability  = "advanced_deliverability" // Enterprise: advanced deliverability
	FeatureSLA             = "sla"                     // Enterprise: SLA guarantees
	FeatureDSAR            = "dsar"                    // Enterprise: data-subject access + erasure (GDPR Art.15/17)
)

// FreeTierFeatures are always available without a license.
var FreeTierFeatures = []string{
	FeatureBasicMail,
}

// ProFeatures require a Pro or higher license.
var ProFeatures = []string{
	FeatureBasicMail,
	FeatureAnalytics,
	FeatureOIDCSSO,
	FeatureCustomBranding,
	FeatureAdvancedSpam,
	FeaturePrioritySupport,
}

// EnterpriseFeatures require an Enterprise license.
var EnterpriseFeatures = []string{
	FeatureBasicMail,
	FeatureAnalytics,
	FeatureOIDCSSO,
	FeatureCustomBranding,
	FeatureAdvancedSpam,
	FeaturePrioritySupport,
	FeatureSAMLSSO,
	FeatureDeliverability,
	FeatureSLA,
	FeatureDSAR,
}

// isFreeTierFeature returns true if the feature is available on the free tier.
func isFreeTierFeature(feature string) bool {
	for _, f := range FreeTierFeatures {
		if f == feature {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// FeatureGateService — wraps Client + Cache for middleware use
// ---------------------------------------------------------------------------

// FeatureGateService provides HTTP middleware for feature-gating based on
// ValidonX license entitlements. When ValidonX is not configured, the install
// is treated as Free tier — only free-tier features (basic_mail) pass; any
// Pro/Enterprise feature is denied with 403 / 402 + upgrade page.
//
// Pre-v0.1.6 the unconfigured path was an "allow everything" bypass; that
// silently exposed every Pro/Enterprise endpoint on Free installs. See
// feedback_featuregate_unconfigured_bypass.md.
//
// The underlying Client is stored in an atomic pointer so the License admin
// API can hot-swap it when an admin saves new credentials, without restarting
// the api container. Read paths use currentClient() which returns nil-safely.
type FeatureGateService struct {
	client atomic.Pointer[Client]
	cache  *LicenseCache
	logger *slog.Logger
}

// NewFeatureGateService creates a FeatureGateService.
// client may be nil (free-tier mode). db is used for the license cache.
func NewFeatureGateService(client *Client, db *pgxpool.Pool, logger *slog.Logger) *FeatureGateService {
	var cache *LicenseCache
	if db != nil {
		cache = NewLicenseCache(db, logger)
	}
	fgs := &FeatureGateService{
		cache:  cache,
		logger: logger,
	}
	fgs.client.Store(client)
	return fgs
}

// currentClient returns the active Client pointer (may be nil). Callers must
// use Configured() to test usability before calling other methods.
func (fgs *FeatureGateService) currentClient() *Client {
	return fgs.client.Load()
}

// SwapClient atomically replaces the underlying Client. Used by the License
// admin API when an admin saves new credentials. Pass nil to deactivate
// (revert to free-tier behaviour).
func (fgs *FeatureGateService) SwapClient(c *Client) {
	fgs.client.Store(c)
	if c.Configured() {
		fgs.logger.Info("validonx client swapped — license activated",
			"tenant_id", c.TenantID(), "server_id", c.ServerID())
	} else {
		fgs.logger.Info("validonx client swapped to free-tier (nil/unconfigured)")
	}
}

// Cache exposes the underlying license cache for handlers that need to
// invalidate or update entries (e.g. License DELETE clearing a tenant row).
// May return nil if the gate was constructed without a DB pool.
func (fgs *FeatureGateService) Cache() *LicenseCache {
	return fgs.cache
}

// ResolveTier returns the licensing tier this install is currently entitled to,
// based on the cached license features. Used by handlers that need to make
// tier-aware decisions outside the request middleware (e.g. Free-tier resource
// caps on domain/mailbox creation, or rendering tier badges).
//
// Returns:
//   - TierFree: ValidonX not configured, or cached license has no Pro/Enterprise features
//   - TierPro: cached license has any Pro feature (custom_branding, analytics, etc.)
//   - TierEnterprise: cached license has any Enterprise feature (saml_sso, dsar, etc.)
//
// On cache miss, performs a single live refresh to populate the cache. On any
// hard failure (no cache, no live answer) returns TierFree as the safe default.
// The grace period is intentionally NOT enforced here — handlers calling this
// for caps want a current view, not a 30-day-stale one. Use FeatureGate for
// access enforcement; ResolveTier for tier-aware UX/limits.
func (fgs *FeatureGateService) ResolveTier(ctx context.Context) (string, error) {
	client := fgs.currentClient()
	if !client.Configured() {
		return TierFree, nil
	}

	tenantID := client.TenantID()

	// Try cache first.
	if fgs.cache != nil {
		cached, err := fgs.cache.GetCached(ctx, tenantID)
		if err == nil && cached != nil {
			return tierFromFeatures(cached.Features), nil
		}
	}

	// Cache miss — try live refresh.
	refreshed, err := fgs.refreshLicense(ctx, tenantID)
	if err != nil {
		return TierFree, err
	}
	if refreshed == nil {
		return TierFree, nil
	}
	return tierFromFeatures(refreshed.Features), nil
}

// tierFromFeatures infers the license tier from an entitlement list.
// The check order matters: Enterprise > Pro > Free. A license that has BOTH
// Pro and Enterprise features (which Enterprise always does) resolves as
// Enterprise.
func tierFromFeatures(features []string) string {
	hasEnterprise := false
	hasPro := false
	for _, f := range features {
		switch f {
		case FeatureSAMLSSO, FeatureDeliverability, FeatureSLA, FeatureDSAR:
			hasEnterprise = true
		case FeatureAnalytics, FeatureOIDCSSO, FeatureCustomBranding,
			FeatureAdvancedSpam, FeaturePrioritySupport:
			hasPro = true
		}
	}
	if hasEnterprise {
		return TierEnterprise
	}
	if hasPro {
		return TierPro
	}
	return TierFree
}

// FeatureGate returns HTTP middleware that checks whether the current license
// allows access to the specified feature.
//
// Behaviour:
//  1. Free-tier features (basic_mail) are always allowed.
//  2. If ValidonX is not configured, the install is Free tier; non-free
//     features are denied with 403 FEATURE_NOT_AVAILABLE.
//  3. Otherwise check the Postgres-cached license for the tenant.
//  4. If the cache is present and not expired, check for the feature.
//  5. If the cache is expired (grace period exceeded), return 403 LICENSE_EXPIRED.
//  6. If no cache exists, attempt a live license check and cache the result.
//  7. If the live check also fails, deny access for non-free features.
func (fgs *FeatureGateService) FeatureGate(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Step 1: Free-tier features are always allowed, regardless of
			// licensing state.
			if isFreeTierFeature(feature) {
				next.ServeHTTP(w, r)
				return
			}

			// Step 2: ValidonX not configured → Free tier → deny non-free
			// features. Pre-v0.1.6 this branch allowed everything; that silently
			// exposed every Pro/Enterprise endpoint on Free installs (see
			// feedback_featuregate_unconfigured_bypass.md).
			client := fgs.currentClient()
			if !client.Configured() {
				writeFeatureError(w, http.StatusForbidden, ErrFeatureNotAvailable,
					"This feature requires a Pro or Enterprise license: "+feature)
				return
			}

			// Step 3: Check cached license.
			ctx := r.Context()
			tenantID := client.TenantID()

			allowed, err := fgs.checkFeatureAccess(ctx, tenantID, feature)
			if err != nil {
				fgs.logger.Error("feature gate check failed",
					"feature", feature,
					"tenant_id", tenantID,
					"error", err,
				)

				// Distinguish license expiry from generic errors.
				var expErr *licenseExpiredError
				if errors.As(err, &expErr) {
					writeFeatureError(w, http.StatusForbidden, ErrLicenseExpired,
						"Your license entitlement has expired — please renew your subscription")
					return
				}

				writeFeatureError(w, http.StatusForbidden, ErrFeatureNotAvailable,
					"Unable to verify license for this feature")
				return
			}

			if !allowed {
				writeFeatureError(w, http.StatusForbidden, ErrFeatureNotAvailable,
					"Your current license does not include this feature: "+feature)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// HasFeature reports whether the current license includes the named feature.
// Used by handlers that need a non-middleware check (e.g. filtering OIDC
// providers out of the public list endpoint when the SSO feature is gated).
//
// Behaviour mirrors FeatureGate's allow path, without writing an HTTP error:
//   - Free-tier features (basic_mail) always available
//   - ValidonX unconfigured → Free tier → only free-tier features available
//   - Otherwise consult the cache, falling back to a live refresh on miss
//
// On any error path that would have caused FeatureGate to deny, returns false.
// Callers that need to distinguish "not entitled" from "couldn't tell" should
// use FeatureGate at the route boundary.
func (fgs *FeatureGateService) HasFeature(ctx context.Context, feature string) bool {
	if isFreeTierFeature(feature) {
		return true
	}
	client := fgs.currentClient()
	if !client.Configured() {
		// Free tier — non-free features are not available. Pre-v0.1.6 this
		// returned true; see feedback_featuregate_unconfigured_bypass.md.
		return false
	}
	allowed, err := fgs.checkFeatureAccess(ctx, client.TenantID(), feature)
	if err != nil {
		return false
	}
	return allowed
}

// FeatureGateBrowser is a request-layer gate for browser-facing endpoints
// (OIDC login redirect, OIDC callback). Behaves identically to FeatureGate
// on the allow path; on deny it content-negotiates so a browser sees a
// friendly upgrade page instead of raw JSON, while API clients keep the
// existing 403 JSON envelope.
//
// Negotiation rule:
//   - Accept header contains "text/html"               → 402 + HTML
//   - Accept is "application/json" (explicit)          → 403 + JSON envelope
//   - Accept is "*/*", missing, or anything else       → 402 + HTML
//
// Browsers default to including text/html in Accept; curl defaults to "*/*";
// XHR clients that care can opt into JSON by setting Accept: application/json.
//
// featureLabel is shown verbatim in the HTML page (e.g. "OIDC single sign-on").
// upgradeURL is rendered as the "Upgrade" link target.
func (fgs *FeatureGateService) FeatureGateBrowser(feature, featureLabel, upgradeURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if isFreeTierFeature(feature) {
				next.ServeHTTP(w, r)
				return
			}

			client := fgs.currentClient()
			if !client.Configured() {
				// Free tier — non-free feature denied. Pre-v0.1.6 this branch
				// passed through; see feedback_featuregate_unconfigured_bypass.md.
				if wantsJSON(r) {
					writeFeatureError(w, http.StatusForbidden, ErrFeatureNotAvailable,
						"This feature requires a Pro or Enterprise license: "+feature)
					return
				}
				writeFeatureUpgradeHTML(w, featureLabel, upgradeURL, false)
				return
			}

			ctx := r.Context()
			tenantID := client.TenantID()

			allowed, err := fgs.checkFeatureAccess(ctx, tenantID, feature)
			if err == nil && allowed {
				next.ServeHTTP(w, r)
				return
			}

			expired := false
			if err != nil {
				fgs.logger.Error("browser feature gate check failed",
					"feature", feature, "tenant_id", tenantID, "error", err)
				var expErr *licenseExpiredError
				if errors.As(err, &expErr) {
					expired = true
				}
			}

			if wantsJSON(r) {
				if expired {
					writeFeatureError(w, http.StatusForbidden, ErrLicenseExpired,
						"Your license entitlement has expired — please renew your subscription")
					return
				}
				writeFeatureError(w, http.StatusForbidden, ErrFeatureNotAvailable,
					"Your current license does not include this feature: "+feature)
				return
			}

			writeFeatureUpgradeHTML(w, featureLabel, upgradeURL, expired)
		})
	}
}

// checkFeatureAccess decides feature entitlement for a tenant using the
// path-2 (5-min cache TTL + grace_period_ends_at) model:
//
//  1. No cache row → live refresh; surface its decision.
//  2. Cache fresh (within CacheTTL) → use cached entitlements; no network.
//  3. Cache stale (past CacheTTL) → attempt live refresh.
//     a. Refresh succeeds → use refreshed entitlements.
//     b. Refresh fails → fall back to the stale cache UNLESS:
//     - cached LicenseData.Valid is false (ValidonX previously said
//     this customer is not entitled — don't undo that on a network
//     blip), OR
//     - the cache is past its offline horizon (see offlineHorizonPassed):
//     grace_period_ends_at when set, else expires_at. Past it we must
//     NOT keep serving Pro from a stale cache.
//     Either condition surfaces as licenseExpiredError → drop to Free.
//
// This separates two concerns that path-1 conflated under a 30-day
// constant: cache freshness (when to try ValidonX again) vs offline
// tolerance (how long to keep working on stale data when ValidonX is
// unreachable). Per the 2026-06-01 ValidonX coordination, ValidonX sets no
// connectivity grace window — offline tolerance is bounded by the license's
// own paid period (expires_at), extended by grace_period_ends_at for the
// past_due / cancel-at-period-end cases. Both are server-authoritative.
func (fgs *FeatureGateService) checkFeatureAccess(ctx context.Context, tenantID, feature string) (bool, error) {
	if fgs.cache == nil {
		return false, nil
	}

	cached, err := fgs.cache.GetCached(ctx, tenantID)
	if err != nil {
		fgs.logger.Warn("failed to read license cache", "error", err)
		// Fall through to live check.
	}

	// No cache row at all — must live-refresh to know anything.
	if cached == nil {
		refreshed, refreshErr := fgs.refreshLicense(ctx, tenantID)
		if refreshErr != nil {
			return false, refreshErr
		}
		if refreshed == nil {
			return false, nil
		}
		return refreshed.HasFeature(feature), nil
	}

	// Cache row present and fresh — happy path, no network call.
	if !cached.IsExpired() {
		return cached.HasFeature(feature), nil
	}

	// Cache row present but stale — try a live refresh.
	refreshed, refreshErr := fgs.refreshLicense(ctx, tenantID)
	if refreshErr == nil {
		return refreshed.HasFeature(feature), nil
	}

	// Refresh failed (ValidonX unreachable, transient error, etc.). Fall
	// back to the stale cache UNLESS the cache itself encodes a hard deny.
	fgs.logger.Warn("license refresh failed, falling back to stale cache",
		"tenant_id", tenantID, "error", refreshErr,
		"cache_age_minutes", time.Since(cached.LastCheckAt).Minutes(),
	)

	if !cached.LicenseData.Valid {
		// ValidonX previously told us this customer is not entitled.
		// A network failure now does NOT re-grant access.
		writeFeatureErrorToLogger(fgs.logger, tenantID, feature)
		return false, &licenseExpiredError{tenantID: tenantID}
	}
	// Offline tolerance is bounded by the license's own horizon, never by
	// cache age. The horizon is grace_period_ends_at when present (it extends
	// past the paid period for past_due dunning and cancel-at-period-end),
	// otherwise expires_at (the paid-through date for a healthy active sub).
	// A nil horizon means a perpetual license — no offline bound. Past the
	// horizon with ValidonX unreachable we require a successful re-resolve
	// before serving Pro again, rather than serving a stale cache forever.
	if offlineHorizonPassed(cached.LicenseData, time.Now()) {
		fgs.logger.Warn("cached license past offline horizon while ValidonX unreachable",
			"tenant_id", tenantID,
			"expires_at", cached.LicenseData.ExpiresAt,
			"grace_period_ends_at", cached.LicenseData.GracePeriodEndsAt,
		)
		writeFeatureErrorToLogger(fgs.logger, tenantID, feature)
		return false, &licenseExpiredError{tenantID: tenantID}
	}

	// Stale cache within the license horizon — serve from it.
	return cached.HasFeature(feature), nil
}

// offlineHorizonPassed reports whether a stale cached license has passed the
// point beyond which Vectis must stop serving Pro while ValidonX is
// unreachable. ValidonX sets no connectivity grace window (per the 2026-06-01
// coordination); the horizon is grace_period_ends_at when present (it covers
// past_due dunning and cancel-at-period-end, which extend past the paid
// period), otherwise expires_at (the paid-through date for a healthy active
// sub). A nil horizon means a perpetual license — no offline bound.
func offlineHorizonPassed(ld LicenseResponse, now time.Time) bool {
	horizon := ld.ExpiresAt
	if ld.GracePeriodEndsAt != nil {
		horizon = ld.GracePeriodEndsAt
	}
	return horizon != nil && now.After(*horizon)
}

// refreshLicense performs a live license check and updates the cache.
func (fgs *FeatureGateService) refreshLicense(ctx context.Context, tenantID string) (*CachedLicense, error) {
	client := fgs.currentClient()
	if client == nil {
		return nil, errClientNotConfigured
	}

	// Path-2: native /api/v1/integration/licensing/resolve endpoint. nil
	// features → ValidonX returns the full entitlement set.
	resp, err := client.CheckLicense(ctx, nil)
	if err != nil {
		fgs.logger.Warn("live license check failed", "tenant_id", tenantID, "error", err)

		// Log the failure as a billing event (best-effort).
		_ = client.LogBillingEvent(ctx, BillingEvent{
			Type:     "error",
			TenantID: tenantID,
			ServerID: client.ServerID(),
			Details:  map[string]any{"error": err.Error(), "action": "license_refresh"},
		})

		return nil, err
	}

	// Update cache.
	if fgs.cache != nil {
		if cacheErr := fgs.cache.UpdateCache(ctx, tenantID, client.subscriptionID, resp); cacheErr != nil {
			fgs.logger.Warn("failed to update license cache", "error", cacheErr)
		}
	}

	// Log successful check.
	_ = client.LogBillingEvent(ctx, BillingEvent{
		Type:     "license.check",
		TenantID: tenantID,
		ServerID: client.ServerID(),
		Details: map[string]any{
			"status":   resp.Status,
			"valid":    resp.Valid,
			"features": resp.AllowedFeatures,
		},
	})

	// Return as CachedLicense for feature checking.
	return &CachedLicense{
		TenantID:    tenantID,
		LicenseData: *resp,
		Features:    resp.AllowedFeatures,
		Status:      resp.Status,
		ExpiresAt:   time.Now().Add(CacheTTL),
	}, nil
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

type licenseExpiredError struct {
	tenantID string
}

func (e *licenseExpiredError) Error() string {
	return "license entitlement expired for tenant " + e.tenantID
}

// featureErrorResponse is the JSON body returned when feature access is denied.
type featureErrorResponse struct {
	Error featureErrorDetail `json:"error"`
	Meta  featureErrorMeta   `json:"meta"`
}

type featureErrorDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type featureErrorMeta struct {
	Timestamp time.Time `json:"timestamp"`
}

func writeFeatureError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(featureErrorResponse{
		Error: featureErrorDetail{
			Code:    code,
			Message: message,
		},
		Meta: featureErrorMeta{
			Timestamp: time.Now().UTC(),
		},
	}); err != nil {
		slog.Error("failed to encode feature error response", "error", err)
	}
}

func writeFeatureErrorToLogger(logger *slog.Logger, tenantID, feature string) {
	logger.Warn("denying access — license entitlement expired (past offline horizon)",
		"tenant_id", tenantID,
		"feature", feature,
	)
}

// wantsJSON returns true when the request's Accept header explicitly prefers
// JSON over HTML. Used by FeatureGateBrowser to choose between the JSON 403
// envelope and the HTML upgrade page.
//
// Decision matrix:
//   - Accept contains "text/html"     → false (HTML wins, even if "application/json" also present)
//   - Accept is exactly "application/json" or "application/json, ..." with no html → true
//   - Accept is "*/*", missing, empty → false (default to HTML for browser-friendliness)
//
// We do not parse q-values; in practice browsers either include text/html or
// they don't, and API clients either send an explicit application/json or
// don't care.
func wantsJSON(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	lower := strings.ToLower(accept)
	if strings.Contains(lower, "text/html") {
		return false
	}
	if strings.Contains(lower, "application/json") {
		return true
	}
	return false
}

// writeFeatureUpgradeHTML renders a small static HTML page explaining that
// the feature requires a paid license, with a link to upgrade. Status is
// 402 Payment Required (semantically accurate for "requires paid plan",
// matches what GitHub/Stripe use for the same scenario).
func writeFeatureUpgradeHTML(w http.ResponseWriter, featureLabel, upgradeURL string, expired bool) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusPaymentRequired)

	heading := "Pro feature"
	body := featureLabel + " requires a Pro license. Your current install is on the Free tier."
	if expired {
		heading = "License expired"
		body = "Your license entitlement has expired. Renew your subscription to continue using " + featureLabel + "."
	}
	if upgradeURL == "" {
		upgradeURL = "https://vectismail.com/pricing"
	}

	page := `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>` + htmlEscape(heading) + ` — Vectis Mail</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
         max-width: 32rem; margin: 4rem auto; padding: 0 1.5rem; color: #0f172a; line-height: 1.5; }
  h1 { font-size: 1.5rem; margin: 0 0 1rem; }
  p { margin: 0 0 1rem; }
  .actions { margin-top: 1.5rem; display: flex; gap: 0.75rem; flex-wrap: wrap; }
  a.btn { display: inline-block; padding: 0.6rem 1.1rem; border-radius: 0.375rem;
          text-decoration: none; font-weight: 500; }
  a.btn-primary { background: #2563eb; color: #fff; }
  a.btn-secondary { background: #e2e8f0; color: #0f172a; }
  .meta { color: #64748b; font-size: 0.85rem; margin-top: 2rem; }
</style>
</head>
<body>
<h1>` + htmlEscape(heading) + `</h1>
<p>` + htmlEscape(body) + `</p>
<div class="actions">
  <a class="btn btn-primary" href="` + htmlEscape(upgradeURL) + `">View pricing</a>
  <a class="btn btn-secondary" href="/admin">Back to sign-in</a>
</div>
<p class="meta">Vectis Mail Server</p>
</body>
</html>`
	_, _ = w.Write([]byte(page))
}

// htmlEscape replaces characters that have special meaning in HTML context
// with their entity equivalents. Used by writeFeatureUpgradeHTML to render
// caller-supplied strings safely.
func htmlEscape(s string) string {
	r := strings.NewReplacer(
		"&", "&amp;",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"'", "&#39;",
	)
	return r.Replace(s)
}
