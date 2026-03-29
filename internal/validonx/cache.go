package validonx

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// GracePeriod is the maximum age of a cached license before the server
// falls back to free-tier behaviour. Per architecture: 30 days.
const GracePeriod = 30 * 24 * time.Hour

// CachedLicense represents a row in the validonx_cache table.
type CachedLicense struct {
	ID             string          `json:"id"`
	TenantID       string          `json:"tenant_id"`
	SubscriptionID string          `json:"subscription_id"`
	LicenseData    LicenseResponse `json:"license_data"`
	Features       []string        `json:"features"`
	Status         string          `json:"status"`
	LastCheckAt    time.Time       `json:"last_check_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// LicenseCache manages cached license entitlements in the validonx_cache table.
type LicenseCache struct {
	db     *pgxpool.Pool
	logger *slog.Logger
}

// NewLicenseCache creates a LicenseCache backed by Postgres.
func NewLicenseCache(db *pgxpool.Pool, logger *slog.Logger) *LicenseCache {
	return &LicenseCache{
		db:     db,
		logger: logger,
	}
}

// GetCached retrieves the cached license for the given tenant.
// Returns nil, nil if no cache entry exists.
func (lc *LicenseCache) GetCached(ctx context.Context, tenantID string) (*CachedLicense, error) {
	row := lc.db.QueryRow(ctx,
		`SELECT id, tenant_id, subscription_id, license_data, features,
		        status, last_check_at, expires_at, created_at, updated_at
		 FROM validonx_cache
		 WHERE tenant_id = $1`, tenantID,
	)

	var cl CachedLicense
	var licenseDataBytes, featuresBytes []byte

	err := row.Scan(
		&cl.ID, &cl.TenantID, &cl.SubscriptionID,
		&licenseDataBytes, &featuresBytes,
		&cl.Status, &cl.LastCheckAt, &cl.ExpiresAt,
		&cl.CreatedAt, &cl.UpdatedAt,
	)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get cached license: %w", err)
	}

	if err := json.Unmarshal(licenseDataBytes, &cl.LicenseData); err != nil {
		return nil, fmt.Errorf("unmarshal cached license_data: %w", err)
	}
	if len(featuresBytes) > 0 {
		if err := json.Unmarshal(featuresBytes, &cl.Features); err != nil {
			return nil, fmt.Errorf("unmarshal cached features: %w", err)
		}
	}

	return &cl, nil
}

// UpdateCache stores or updates the cached license for the given tenant.
// The grace-period expiry is set to 30 days from now.
func (lc *LicenseCache) UpdateCache(ctx context.Context, tenantID string, subscriptionID string, resp *LicenseResponse) error {
	licenseDataBytes, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal license_data: %w", err)
	}

	featuresBytes, err := json.Marshal(resp.AllowedFeatures)
	if err != nil {
		return fmt.Errorf("marshal features: %w", err)
	}

	now := time.Now().UTC()
	expiresAt := now.Add(GracePeriod)

	_, err = lc.db.Exec(ctx,
		`INSERT INTO validonx_cache
		    (id, tenant_id, subscription_id, license_data, features, status, last_check_at, expires_at, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		 ON CONFLICT (tenant_id) DO UPDATE SET
		    subscription_id = EXCLUDED.subscription_id,
		    license_data    = EXCLUDED.license_data,
		    features        = EXCLUDED.features,
		    status          = EXCLUDED.status,
		    last_check_at   = EXCLUDED.last_check_at,
		    expires_at      = EXCLUDED.expires_at,
		    updated_at      = EXCLUDED.updated_at`,
		types.NewUUIDv7(), tenantID, subscriptionID,
		licenseDataBytes, featuresBytes,
		resp.Status, now, expiresAt, now, now,
	)
	if err != nil {
		return fmt.Errorf("upsert cached license: %w", err)
	}

	lc.logger.Info("license cache updated",
		"tenant_id", tenantID,
		"status", resp.Status,
		"features", resp.AllowedFeatures,
		"expires_at", expiresAt,
	)
	return nil
}

// IsExpired returns true if the cached license grace period has elapsed.
func (cl *CachedLicense) IsExpired() bool {
	return time.Now().After(cl.ExpiresAt)
}

// HasFeature returns true if the cached license includes the given feature.
func (cl *CachedLicense) HasFeature(feature string) bool {
	for _, f := range cl.Features {
		if f == feature {
			return true
		}
	}
	// Also check the LicenseData.AllowedFeatures for completeness.
	for _, f := range cl.LicenseData.AllowedFeatures {
		if f == feature {
			return true
		}
	}
	return false
}

// DeleteCached removes the cached license for a tenant.
func (lc *LicenseCache) DeleteCached(ctx context.Context, tenantID string) error {
	_, err := lc.db.Exec(ctx,
		`DELETE FROM validonx_cache WHERE tenant_id = $1`, tenantID,
	)
	if err != nil {
		return fmt.Errorf("delete cached license: %w", err)
	}
	return nil
}
