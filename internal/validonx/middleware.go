package validonx

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
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
	FeatureBasicMail        = "basic_mail"        // domains, mailboxes, aliases
	FeatureCustomBranding   = "custom_branding"    // Pro: custom branding
	FeatureAdvancedSpam     = "advanced_spam"       // Pro: advanced spam config
	FeaturePrioritySupport  = "priority_support"    // Pro: priority support
	FeatureMultiTenant      = "multi_tenant"        // Enterprise: multi-tenant
	FeatureDeliverability   = "advanced_deliverability" // Enterprise: advanced deliverability
	FeatureSLA              = "sla"                 // Enterprise: SLA guarantees
)

// FreeTierFeatures are always available without a license.
var FreeTierFeatures = []string{
	FeatureBasicMail,
}

// ProFeatures require a Pro or higher license.
var ProFeatures = []string{
	FeatureBasicMail,
	FeatureCustomBranding,
	FeatureAdvancedSpam,
	FeaturePrioritySupport,
}

// EnterpriseFeatures require an Enterprise license.
var EnterpriseFeatures = []string{
	FeatureBasicMail,
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
type FeatureGateService struct {
	client *Client
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
	return &FeatureGateService{
		client: client,
		cache:  cache,
		logger: logger,
	}
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
			// Step 1: ValidonX not configured — free tier, allow everything.
			if !fgs.client.Configured() {
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
			tenantID := fgs.client.TenantID()

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
	if fgs.client == nil {
		return nil, errClientNotConfigured
	}

	resp, err := fgs.client.CheckLicense(ctx, nil) // check all features
	if err != nil {
		fgs.logger.Warn("live license check failed", "tenant_id", tenantID, "error", err)

		// Log the failure as a billing event (best-effort).
		_ = fgs.client.LogBillingEvent(ctx, BillingEvent{
			Type:     "error",
			TenantID: tenantID,
			ServerID: fgs.client.ServerID(),
			Details:  map[string]any{"error": err.Error(), "action": "license_refresh"},
		})

		return nil, err
	}

	// Update cache.
	if fgs.cache != nil {
		if cacheErr := fgs.cache.UpdateCache(ctx, tenantID, fgs.client.subscriptionID, resp); cacheErr != nil {
			fgs.logger.Warn("failed to update license cache", "error", cacheErr)
		}
	}

	// Log successful check.
	_ = fgs.client.LogBillingEvent(ctx, BillingEvent{
		Type:     "license.check",
		TenantID: tenantID,
		ServerID: fgs.client.ServerID(),
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
