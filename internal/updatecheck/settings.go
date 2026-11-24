package updatecheck

import (
	"context"
	"errors"
	"fmt"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Settings is the effective on/off state of the update check, combining the
// admin-dashboard switches (update_check_config, migration 000028) with
// config.yaml.
type Settings struct {
	CheckEnabled bool `json:"check_enabled"` // daily check runs
	EmailEnabled bool `json:"email_enabled"` // a new release is emailed to the admin
	// CheckLocked / EmailLocked: config.yaml explicitly turns this off, so the
	// dashboard switch can't turn it back on.
	CheckLocked bool `json:"check_locked"`
	EmailLocked bool `json:"email_locked"`
	// Switchable is false while the update_check_config table doesn't exist
	// (an install updated by an orchestrator that predates migration 000028).
	// The dashboard then hides the switches and config.yaml alone applies.
	Switchable bool `json:"switchable"`
}

// Stored is the dashboard's saved choice (one row in update_check_config).
type Stored struct {
	CheckEnabled bool
	EmailEnabled bool
}

// Effective combines config.yaml with the dashboard's saved choice (nil = never
// saved). An explicit `false` in config.yaml wins and locks the switch; an
// explicit `true` there is the same as the default, so the dashboard can still
// turn it off. Email can only be on while the check is on.
func Effective(file config.UpdatesConfig, stored *Stored, switchable bool) Settings {
	checkLocked := file.Check != nil && !*file.Check
	emailLocked := checkLocked || (file.Email != nil && !*file.Email)
	check := !checkLocked && (stored == nil || stored.CheckEnabled)
	email := check && !emailLocked && (stored == nil || stored.EmailEnabled)
	return Settings{
		CheckEnabled: check,
		EmailEnabled: email,
		CheckLocked:  checkLocked,
		EmailLocked:  emailLocked,
		Switchable:   switchable,
	}
}

// pgUndefinedTable is Postgres's SQLSTATE for "relation does not exist".
const pgUndefinedTable = "42P01"

// LoadStored reads the dashboard's saved choice. It returns (nil, true, nil)
// when nothing has been saved, and (nil, false, nil) when the table doesn't
// exist yet, so callers fall back to config.yaml instead of failing.
func LoadStored(ctx context.Context, db *pgxpool.Pool) (stored *Stored, switchable bool, err error) {
	if db == nil {
		return nil, false, errors.New("load update-check settings: db pool is nil")
	}
	var s Stored
	err = db.QueryRow(ctx,
		`SELECT check_enabled, email_enabled FROM update_check_config WHERE singleton = TRUE`,
	).Scan(&s.CheckEnabled, &s.EmailEnabled)
	switch {
	case err == nil:
		return &s, true, nil
	case errors.Is(err, pgx.ErrNoRows):
		return nil, true, nil
	case isUndefinedTable(err):
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("read update_check_config: %w", err)
	}
}

// ErrNotSwitchable is returned by SaveStored while the table doesn't exist.
var ErrNotSwitchable = errors.New("update-check switches need migration 000028, which runs at the next update")

// SaveStored upserts the dashboard's choice. configuredByAdminID is kept for
// the audit trail ("" for a system write).
func SaveStored(ctx context.Context, db *pgxpool.Pool, s Stored, configuredByAdminID string) error {
	if db == nil {
		return errors.New("save update-check settings: db pool is nil")
	}
	var adminID any
	if configuredByAdminID != "" {
		adminID = configuredByAdminID
	}
	_, err := db.Exec(ctx,
		`INSERT INTO update_check_config
		    (singleton, check_enabled, email_enabled, configured_at, configured_by_admin_id)
		 VALUES (TRUE, $1, $2, NOW(), $3)
		 ON CONFLICT (singleton) DO UPDATE SET
		    check_enabled          = EXCLUDED.check_enabled,
		    email_enabled          = EXCLUDED.email_enabled,
		    configured_at          = NOW(),
		    configured_by_admin_id = EXCLUDED.configured_by_admin_id`,
		s.CheckEnabled, s.EmailEnabled, adminID,
	)
	if isUndefinedTable(err) {
		return ErrNotSwitchable
	}
	if err != nil {
		return fmt.Errorf("upsert update_check_config: %w", err)
	}
	return nil
}

func isUndefinedTable(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == pgUndefinedTable
}
