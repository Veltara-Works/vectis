// Package branding holds the admin-UI customisation Pro feature
// (custom_branding). The shape is deliberately tiny: a singleton DB row
// with three fields. Reads are unauthenticated-feature-wise (the chrome
// always asks; Free installs get defaults). Writes are gated behind the
// custom_branding feature in the API layer.
package branding

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Defaults are the built-in Vectis values used when the DB row is empty.
// Keep them aligned with what the React chrome would render before any
// /branding response arrives — same product name, same accent colour.
const (
	DefaultProductName  = "Vectis Mail"
	DefaultPrimaryColor = "#3b82f6"
	DefaultLogoURL      = ""
)

// Config is the wire shape returned by GET /branding and accepted by PUT.
// Empty strings are valid on input — they revert that field to the default
// at render time.
type Config struct {
	ProductName  string
	PrimaryColor string
	LogoURL      string
	FromDB       bool
}

// Effective returns the config with empty fields filled in from the
// built-in defaults. The chrome consumes this directly.
func (c Config) Effective() Config {
	out := c
	if out.ProductName == "" {
		out.ProductName = DefaultProductName
	}
	if out.PrimaryColor == "" {
		out.PrimaryColor = DefaultPrimaryColor
	}
	return out
}

// hexColorRE matches #RGB / #RRGGBB / #RRGGBBAA. Anything else is rejected
// at the API layer to keep us out of the CSS-injection neighbourhood.
var hexColorRE = regexp.MustCompile(`^#([0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$`)

// Validate enforces the small set of input invariants. Returns nil for an
// all-empty config (which is a valid clear-to-defaults).
func (c Config) Validate() error {
	if c.PrimaryColor != "" && !hexColorRE.MatchString(c.PrimaryColor) {
		return errors.New("primary_color must be a hex string like #3b82f6")
	}
	if c.LogoURL != "" {
		// Allow https:// (operator-hosted) and a single in-app prefix
		// for assets we ship later. Reject everything else — javascript:,
		// data:, http:// etc. all out.
		if !strings.HasPrefix(c.LogoURL, "https://") && !strings.HasPrefix(c.LogoURL, "/assets/") {
			return errors.New("logo_url must be an https:// URL or /assets/ path")
		}
		if len(c.LogoURL) > 2048 {
			return errors.New("logo_url too long (max 2048)")
		}
	}
	if len(c.ProductName) > 64 {
		return errors.New("product_name too long (max 64)")
	}
	return nil
}

// LoadConfig reads the singleton row. Returns a zero Config + FromDB=false
// when the row is absent.
func LoadConfig(ctx context.Context, db *pgxpool.Pool) (Config, error) {
	cfg := Config{}
	if db == nil {
		return cfg, errors.New("load branding config: db pool is nil")
	}

	var name, color, logo string
	err := db.QueryRow(ctx,
		`SELECT product_name, primary_color, logo_url
		   FROM branding_config WHERE singleton = TRUE`,
	).Scan(&name, &color, &logo)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return cfg, nil
		}
		return cfg, fmt.Errorf("read branding_config: %w", err)
	}

	cfg.ProductName = name
	cfg.PrimaryColor = color
	cfg.LogoURL = logo
	cfg.FromDB = true
	return cfg, nil
}

// SaveConfig upserts the singleton row. configuredByAdminID is captured
// for the audit trail; pass empty string for system writes.
func SaveConfig(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger,
	cfg Config, configuredByAdminID string) error {

	if db == nil {
		return errors.New("save branding config: db pool is nil")
	}
	if err := cfg.Validate(); err != nil {
		return err
	}

	var adminID any
	if configuredByAdminID != "" {
		adminID = configuredByAdminID
	}

	_, err := db.Exec(ctx,
		`INSERT INTO branding_config
		    (singleton, product_name, primary_color, logo_url, configured_at, configured_by_admin_id)
		 VALUES (TRUE, $1, $2, $3, NOW(), $4)
		 ON CONFLICT (singleton) DO UPDATE SET
		    product_name           = EXCLUDED.product_name,
		    primary_color          = EXCLUDED.primary_color,
		    logo_url               = EXCLUDED.logo_url,
		    configured_at          = NOW(),
		    configured_by_admin_id = EXCLUDED.configured_by_admin_id`,
		cfg.ProductName, cfg.PrimaryColor, cfg.LogoURL, adminID,
	)
	if err != nil {
		return fmt.Errorf("upsert branding_config: %w", err)
	}
	logger.Info("branding config saved",
		"product_name", cfg.ProductName,
		"primary_color", cfg.PrimaryColor,
		"has_logo", cfg.LogoURL != "",
	)
	return nil
}

// ClearConfig deletes the singleton row, reverting the install to defaults.
func ClearConfig(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger) error {
	if db == nil {
		return errors.New("clear branding config: db pool is nil")
	}
	_, err := db.Exec(ctx, `DELETE FROM branding_config WHERE singleton = TRUE`)
	if err != nil {
		return fmt.Errorf("delete branding_config: %w", err)
	}
	logger.Info("branding config cleared")
	return nil
}
