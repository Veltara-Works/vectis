package validonx

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
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
	FeatureBasicMail        = "basic_mail"             // domains, mailboxes, aliases
	FeatureAnalytics        = "analytics"              // Pro: per-domain analytics dashboard
	FeatureOIDCSSO          = "oidc_sso"               // Pro: OIDC single sign-on
	FeatureCustomBranding   = "custom_branding"        // Pro: custom branding
	FeatureAdvancedSpam     = "advanced_spam"          // Pro: advanced spam config
	FeaturePrioritySupport  = "priority_support"       // Pro: priority support
	FeatureMultiTenant      = "multi_tenant"           // Enterprise: multi-tenant
	FeatureDeliverability   = "advanced_deliverability" // Enterprise: advanced deliverability
	FeatureSLA              = "sla"                    // Enterprise: SLA guarantees
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
	FeatureMultiTenant,
	FeatureDeliverability,
	FeatureSLA,
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
// ValidonX license entitlements. When ValidonX is not configured, all
// requests are allowed (free-tier behaviour).
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
//   - TierEnterprise: cached license has any Enterprise feature (multi_tenant, etc.)
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
		case FeatureMultiTenant, FeatureDeliverability, FeatureSLA:
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
//  1. If ValidonX is not configured (client is nil), allow all requests (free tier).
//  2. Free-tier features (basic_mail) are always allowed regardless of license.
//  3. Check the Postgres-cached license for the tenant.
//  4. If the cache is present and not expired, check for the feature.
//  5. If the cache is expired (grace period exceeded), return 403 LICENSE_EXPIRED.
//  6. If no cache exists, attempt a live license check and cache the result.
//  7. If the live check also fails, deny access for non-free features.
func (fgs *FeatureGateService) FeatureGate(feature string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			client := fgs.currentClient()

			// Step 1: ValidonX not configured — free tier, allow everything.
			if !client.Configured() {
				next.ServeHTTP(w, r)
				return
			}

			// Step 2: Free-tier features are always allowed.
			if isFreeTierFeature(feature) {
				next.ServeHTTP(w, r)
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
						"License grace period has expired — please renew your subscription")
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

// checkFeatureAccess checks the cache and optionally the live API for feature access.
func (fgs *FeatureGateService) checkFeatureAccess(ctx context.Context, tenantID, feature string) (bool, error) {
	if fgs.cache == nil {
		return false, nil
	}

	// Try cache first.
	cached, err := fgs.cache.GetCached(ctx, tenantID)
	if err != nil {
		fgs.logger.Warn("failed to read license cache", "error", err)
		// Fall through to live check.
	}

	if cached != nil {
		// Check grace period.
		if cached.IsExpired() {
			fgs.logger.Warn("cached license grace period expired",
				"tenant_id", tenantID,
				"expired_at", cached.ExpiresAt,
			)
			// Try a live refresh before giving up.
			refreshed, refreshErr := fgs.refreshLicense(ctx, tenantID)
			if refreshErr != nil {
				// Grace period truly expired and can't reach ValidonX.
				writeFeatureErrorToLogger(fgs.logger, tenantID, feature)
				return false, &licenseExpiredError{tenantID: tenantID}
			}
			return refreshed.HasFeature(feature), nil
		}
		return cached.HasFeature(feature), nil
	}

	// No cache — try live check.
	refreshed, err := fgs.refreshLicense(ctx, tenantID)
	if err != nil {
		return false, err
	}
	if refreshed == nil {
		return false, nil
	}
	return refreshed.HasFeature(feature), nil
}

// refreshLicense performs a live license check and updates the cache.
func (fgs *FeatureGateService) refreshLicense(ctx context.Context, tenantID string) (*CachedLicense, error) {
	client := fgs.currentClient()
	if client == nil {
		return nil, errClientNotConfigured
	}

	// During v0.1.0-beta1 we call ValidonX's existing /api/v1/integration/
	// entitlements/check endpoint via the path1 adapter (see path1.go).
	// Path-2's /v1/licensing/resolve will replace this with c.CheckLicense.
	// Single-line revert when that ships.
	resp, err := client.CheckLicensePath1(ctx, nil) // check all features
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
		ExpiresAt:   time.Now().Add(GracePeriod),
	}, nil
}

// ---------------------------------------------------------------------------
// Error helpers
// ---------------------------------------------------------------------------

type licenseExpiredError struct {
	tenantID string
}

func (e *licenseExpiredError) Error() string {
	return "license grace period expired for tenant " + e.tenantID
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
	logger.Warn("denying access — license grace period expired",
		"tenant_id", tenantID,
		"feature", feature,
	)
}
