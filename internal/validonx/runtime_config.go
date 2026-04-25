package validonx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/config"
)

// DefaultBaseURL is used when neither secrets.yaml nor the validonx_config DB
// row provides one. ValidonX's production endpoint.
const DefaultBaseURL = "https://api.validonx.com"

// RuntimeConfig holds the merged ValidonX configuration sourced from the DB
// (validonx_config singleton row) with fall-through to secrets.yaml. The DB
// is authoritative when populated; secrets.yaml is the seed value used at
// install time and as a fallback when the DB row is empty.
type RuntimeConfig struct {
	BaseURL        string
	ServiceKey     string
	TenantID       string
	SubscriptionID string
	ServerID       string
	// FromDB indicates the config came from the validonx_config table (admin
	// UI activation), not secrets.yaml. Used for telemetry/UX.
	FromDB bool
}

// IsConfigured returns true when the merged config has the minimum fields
// required to talk to ValidonX (base_url + service_key).
func (c *RuntimeConfig) IsConfigured() bool {
	return c != nil && c.BaseURL != "" && c.ServiceKey != ""
}

// ToSecrets converts the runtime config into the ValidonXSecrets shape that
// NewClient consumes. Returns nil when not configured.
func (c *RuntimeConfig) ToSecrets() *config.ValidonXSecrets {
	if !c.IsConfigured() {
		return nil
	}
	return &config.ValidonXSecrets{
		BaseURL:        c.BaseURL,
		ServiceKey:     c.ServiceKey,
		TenantID:       c.TenantID,
		SubscriptionID: c.SubscriptionID,
		ServerID:       c.ServerID,
	}
}

// LoadRuntimeConfig builds the effective ValidonX config from the
// validonx_config DB row (taking precedence) merged with secrets.yaml (fallback).
//
// Field-level merge semantics: a non-empty DB field overrides the secrets
// equivalent; an empty DB field uses the secrets value. This lets the admin
// UI overwrite just the subscription_id without re-pasting the service_key.
//
// When the DB row is absent or both sources are empty, returns a RuntimeConfig
// with empty fields (IsConfigured() == false → free-tier mode).
func LoadRuntimeConfig(ctx context.Context, db *pgxpool.Pool, secrets *config.ValidonXSecrets) (*RuntimeConfig, error) {
	cfg := &RuntimeConfig{}

	if secrets != nil {
		cfg.BaseURL = secrets.BaseURL
		cfg.ServiceKey = secrets.ServiceKey
		cfg.TenantID = secrets.TenantID
		cfg.SubscriptionID = secrets.SubscriptionID
		cfg.ServerID = secrets.ServerID
	}

	if db != nil {
		var dbBase, dbKey, dbTenant, dbSub, dbServer string
		err := db.QueryRow(ctx,
			`SELECT base_url, service_key, tenant_id, subscription_id, server_id
			 FROM validonx_config WHERE singleton = TRUE`,
		).Scan(&dbBase, &dbKey, &dbTenant, &dbSub, &dbServer)

		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return cfg, fmt.Errorf("read validonx_config: %w", err)
		}
		if err == nil {
			cfg.FromDB = true
			if dbBase != "" {
				cfg.BaseURL = dbBase
			}
			if dbKey != "" {
				cfg.ServiceKey = dbKey
			}
			if dbTenant != "" {
				cfg.TenantID = dbTenant
			}
			if dbSub != "" {
				cfg.SubscriptionID = dbSub
			}
			if dbServer != "" {
				cfg.ServerID = dbServer
			}
		}
	}

	if cfg.IsConfigured() && cfg.BaseURL == "" {
		cfg.BaseURL = DefaultBaseURL
	}

	return cfg, nil
}

// SaveRuntimeConfig writes the given config to the validonx_config singleton
// table. configuredByAdminID is captured for the audit trail. Empty strings
// in the input clear the corresponding DB fields.
func SaveRuntimeConfig(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger,
	cfg RuntimeConfig, configuredByAdminID string) error {

	if db == nil {
		return errors.New("save runtime config: db pool is nil")
	}

	var adminID any
	if configuredByAdminID != "" {
		adminID = configuredByAdminID
	}

	_, err := db.Exec(ctx,
		`INSERT INTO validonx_config
		    (singleton, base_url, service_key, tenant_id, subscription_id, server_id, configured_at, configured_by_admin_id)
		 VALUES (TRUE, $1, $2, $3, $4, $5, NOW(), $6)
		 ON CONFLICT (singleton) DO UPDATE SET
		    base_url               = EXCLUDED.base_url,
		    service_key            = EXCLUDED.service_key,
		    tenant_id              = EXCLUDED.tenant_id,
		    subscription_id        = EXCLUDED.subscription_id,
		    server_id              = EXCLUDED.server_id,
		    configured_at          = NOW(),
		    configured_by_admin_id = EXCLUDED.configured_by_admin_id`,
		cfg.BaseURL, cfg.ServiceKey, cfg.TenantID, cfg.SubscriptionID, cfg.ServerID, adminID,
	)
	if err != nil {
		return fmt.Errorf("upsert validonx_config: %w", err)
	}
	logger.Info("validonx runtime config saved",
		"tenant_id", cfg.TenantID,
		"subscription_id", cfg.SubscriptionID,
	)
	return nil
}

// ClearRuntimeConfig removes the validonx_config row, reverting the install to
// secrets.yaml-only behaviour (or Free tier if secrets is also empty).
func ClearRuntimeConfig(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger) error {
	if db == nil {
		return errors.New("clear runtime config: db pool is nil")
	}
	_, err := db.Exec(ctx, `DELETE FROM validonx_config WHERE singleton = TRUE`)
	if err != nil {
		return fmt.Errorf("delete validonx_config: %w", err)
	}
	logger.Info("validonx runtime config cleared")
	return nil
}
