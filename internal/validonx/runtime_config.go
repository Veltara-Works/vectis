package validonx

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/secretcrypto"
)

// ConfigEncKeyLabel is the HKDF label for the key that encrypts the two
// recoverable credentials in validonx_config (service_key + license_key) at
// rest. Derive with secretcrypto.DeriveKey(master, ConfigEncKeyLabel). The
// service_key is a live ValidonX partner X-API-Key and the license_key resolves
// a paying tenant, so both follow the repo's at-rest-encryption convention
// (mirrors WebhookRepo / IMAPImportRepo). tenant_id/server_id/subscription_id
// are identifiers, not secrets, and stay plaintext.
const ConfigEncKeyLabel = "vectis-validonx-config-v1"

// encryptField encrypts a validonx_config credential for storage. An empty
// value stays empty so the "empty string clears the field" upsert/merge
// semantics survive (Encrypt("") would otherwise yield a non-empty ciphertext).
func encryptField(encKey []byte, val string) (string, error) {
	if val == "" {
		return "", nil
	}
	return secretcrypto.Encrypt(encKey, val)
}

// decryptField reverses encryptField. secretcrypto.Decrypt passes through any
// value lacking the enc:v1: prefix, so legacy plaintext rows (and secrets.yaml
// values, which are never encrypted) round-trip unchanged even with a nil key.
func decryptField(encKey []byte, val string) (string, error) {
	if val == "" {
		return "", nil
	}
	return secretcrypto.Decrypt(encKey, val)
}

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
	// LicenseKey is the ValidonX-issued license string. Sent on the wire
	// to ValidonX's licensing-resolve endpoint. Sourced from the
	// validonx_config DB row when set via admin UI; falls back to
	// secrets.yaml at install time.
	LicenseKey string
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
		LicenseKey:     c.LicenseKey,
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
//
// encKey decrypts the two at-rest-encrypted credentials (service_key,
// license_key) read from the DB row; pass the key derived with ConfigEncKeyLabel.
// A nil key still works for legacy plaintext rows (Decrypt passes them through).
func LoadRuntimeConfig(ctx context.Context, db *pgxpool.Pool, secrets *config.ValidonXSecrets, encKey []byte) (*RuntimeConfig, error) {
	cfg := &RuntimeConfig{}

	if secrets != nil {
		cfg.BaseURL = secrets.BaseURL
		cfg.ServiceKey = secrets.ServiceKey
		cfg.TenantID = secrets.TenantID
		cfg.SubscriptionID = secrets.SubscriptionID
		cfg.ServerID = secrets.ServerID
		cfg.LicenseKey = secrets.LicenseKey
	}

	if db != nil {
		var dbBase, dbKey, dbTenant, dbSub, dbServer, dbLicense string
		err := db.QueryRow(ctx,
			`SELECT base_url, service_key, tenant_id, subscription_id, server_id, license_key
			 FROM validonx_config WHERE singleton = TRUE`,
		).Scan(&dbBase, &dbKey, &dbTenant, &dbSub, &dbServer, &dbLicense)

		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return cfg, fmt.Errorf("read validonx_config: %w", err)
		}
		if err == nil {
			cfg.FromDB = true
			// service_key + license_key are encrypted at rest; decrypt before
			// the field-level merge (Decrypt is a no-op on legacy plaintext rows).
			if dbKey, err = decryptField(encKey, dbKey); err != nil {
				return cfg, fmt.Errorf("decrypt validonx_config service_key: %w", err)
			}
			if dbLicense, err = decryptField(encKey, dbLicense); err != nil {
				return cfg, fmt.Errorf("decrypt validonx_config license_key: %w", err)
			}
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
			if dbLicense != "" {
				cfg.LicenseKey = dbLicense
			}
		}
	}

	// A service_key with no explicit base_url (neither secrets.yaml nor the DB
	// row set one) must resolve against ValidonX's default endpoint, not silently
	// drop to Free (audit F-R2). The previous guard checked IsConfigured() first,
	// which already requires BaseURL != "", so the fallback was dead code and a
	// paying service_key-only install lost its Pro/Enterprise entitlement.
	if cfg.BaseURL == "" && cfg.ServiceKey != "" {
		cfg.BaseURL = DefaultBaseURL
	}

	return cfg, nil
}

// SaveRuntimeConfig writes the given config to the validonx_config singleton
// table. configuredByAdminID is captured for the audit trail. Empty strings
// in the input clear the corresponding DB fields.
//
// encKey encrypts the service_key + license_key at rest (derive with
// ConfigEncKeyLabel). Empty credentials stay empty so a caller can still clear
// a field by passing "".
func SaveRuntimeConfig(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger,
	cfg RuntimeConfig, configuredByAdminID string, encKey []byte) error {

	if db == nil {
		return errors.New("save runtime config: db pool is nil")
	}

	var adminID any
	if configuredByAdminID != "" {
		adminID = configuredByAdminID
	}

	encServiceKey, err := encryptField(encKey, cfg.ServiceKey)
	if err != nil {
		return fmt.Errorf("encrypt validonx_config service_key: %w", err)
	}
	encLicenseKey, err := encryptField(encKey, cfg.LicenseKey)
	if err != nil {
		return fmt.Errorf("encrypt validonx_config license_key: %w", err)
	}

	_, err = db.Exec(ctx,
		`INSERT INTO validonx_config
		    (singleton, base_url, service_key, tenant_id, subscription_id, server_id, license_key, configured_at, configured_by_admin_id)
		 VALUES (TRUE, $1, $2, $3, $4, $5, $6, NOW(), $7)
		 ON CONFLICT (singleton) DO UPDATE SET
		    base_url               = EXCLUDED.base_url,
		    service_key            = EXCLUDED.service_key,
		    tenant_id              = EXCLUDED.tenant_id,
		    subscription_id        = EXCLUDED.subscription_id,
		    server_id              = EXCLUDED.server_id,
		    license_key            = EXCLUDED.license_key,
		    configured_at          = NOW(),
		    configured_by_admin_id = EXCLUDED.configured_by_admin_id`,
		cfg.BaseURL, encServiceKey, cfg.TenantID, cfg.SubscriptionID, cfg.ServerID, encLicenseKey, adminID,
	)
	if err != nil {
		return fmt.Errorf("upsert validonx_config: %w", err)
	}
	// subscription_id is deliberately omitted from the log — the API masks it
	// everywhere (maskSubscriptionID) because the full id identifies a paying
	// customer. tenant_id is enough to correlate the activation (VX-CFG-2).
	logger.Info("validonx runtime config saved",
		"tenant_id", cfg.TenantID,
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

// EncryptLegacyValidonXConfig is an idempotent startup pass that encrypts the
// service_key and license_key of the singleton validonx_config row if they are
// still stored as plaintext (rows written before encryption at rest landed —
// VX-CFG-1). It returns the number of fields migrated (0, 1, or 2). Safe to run
// on every boot: already-encrypted fields and empty fields are skipped, and no
// row (Free install) is a clean 0. Mirrors WebhookRepo.EncryptLegacySecrets.
func EncryptLegacyValidonXConfig(ctx context.Context, db *pgxpool.Pool, encKey []byte) (int, error) {
	if db == nil {
		return 0, errors.New("encrypt legacy validonx_config: db pool is nil")
	}

	var svcKey, licKey string
	err := db.QueryRow(ctx,
		`SELECT service_key, license_key FROM validonx_config WHERE singleton = TRUE`,
	).Scan(&svcKey, &licKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("read validonx_config: %w", err)
	}

	newSvc, svcLegacy := svcKey, svcKey != "" && !secretcrypto.IsEncrypted(svcKey)
	newLic, licLegacy := licKey, licKey != "" && !secretcrypto.IsEncrypted(licKey)
	if !svcLegacy && !licLegacy {
		return 0, nil
	}

	migrated := 0
	if svcLegacy {
		if newSvc, err = secretcrypto.Encrypt(encKey, svcKey); err != nil {
			return 0, fmt.Errorf("encrypt legacy service_key: %w", err)
		}
		migrated++
	}
	if licLegacy {
		if newLic, err = secretcrypto.Encrypt(encKey, licKey); err != nil {
			return migrated, fmt.Errorf("encrypt legacy license_key: %w", err)
		}
		migrated++
	}

	if _, err := db.Exec(ctx,
		`UPDATE validonx_config SET service_key = $1, license_key = $2 WHERE singleton = TRUE`,
		newSvc, newLic,
	); err != nil {
		return 0, fmt.Errorf("update legacy validonx_config: %w", err)
	}
	return migrated, nil
}
