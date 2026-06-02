package backup

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Settings is the runtime-editable backup configuration persisted in the
// backup_config singleton table. When a row is present (FromDB=true) it is
// authoritative; when absent the caller falls back to the file config
// (config.yaml `backup:`). Mirrors the branding.Config / validonx
// runtime-config singleton pattern.
type Settings struct {
	Enabled    bool
	Schedule   string // 5-field cron, e.g. "0 2 * * *"
	Timezone   string // IANA tz (e.g. "Australia/Sydney"); "" = UTC/container-local
	RetainDays int
	FromDB     bool
}

// Validate enforces the input invariants. A schedule is always required (the
// UI keeps the last schedule even when backups are toggled off) and must
// parse; the timezone, when set, must be a known IANA location.
func (s Settings) Validate() error {
	if strings.TrimSpace(s.Schedule) == "" {
		return errors.New("schedule is required")
	}
	if s.RetainDays < 0 {
		return errors.New("retain_days must be >= 0")
	}
	// buildCronSchedule validates both the cron expression and the timezone.
	if _, err := buildCronSchedule(s.Schedule, s.Timezone); err != nil {
		return err
	}
	return nil
}

// LoadSettings reads the singleton row. Returns a zero Settings + FromDB=false
// when the row is absent.
func LoadSettings(ctx context.Context, db *pgxpool.Pool) (Settings, error) {
	out := Settings{}
	if db == nil {
		return out, errors.New("load backup settings: db pool is nil")
	}

	var enabled bool
	var schedule, tz string
	var retain int
	err := db.QueryRow(ctx,
		`SELECT enabled, schedule, timezone, retain_days
		   FROM backup_config WHERE singleton = TRUE`,
	).Scan(&enabled, &schedule, &tz, &retain)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return out, nil
		}
		return out, fmt.Errorf("read backup_config: %w", err)
	}

	out.Enabled = enabled
	out.Schedule = schedule
	out.Timezone = tz
	out.RetainDays = retain
	out.FromDB = true
	return out, nil
}

// SaveSettings upserts the singleton row. configuredByAdminID is captured for
// the audit trail; pass empty string for system writes.
func SaveSettings(ctx context.Context, db *pgxpool.Pool, logger *slog.Logger,
	s Settings, configuredByAdminID string) error {

	if db == nil {
		return errors.New("save backup settings: db pool is nil")
	}
	if err := s.Validate(); err != nil {
		return err
	}

	var adminID any
	if configuredByAdminID != "" {
		adminID = configuredByAdminID
	}

	_, err := db.Exec(ctx,
		`INSERT INTO backup_config
		    (singleton, enabled, schedule, timezone, retain_days, configured_at, configured_by_admin_id)
		 VALUES (TRUE, $1, $2, $3, $4, NOW(), $5)
		 ON CONFLICT (singleton) DO UPDATE SET
		    enabled                = EXCLUDED.enabled,
		    schedule               = EXCLUDED.schedule,
		    timezone               = EXCLUDED.timezone,
		    retain_days            = EXCLUDED.retain_days,
		    configured_at          = NOW(),
		    configured_by_admin_id = EXCLUDED.configured_by_admin_id`,
		s.Enabled, strings.TrimSpace(s.Schedule), strings.TrimSpace(s.Timezone), s.RetainDays, adminID,
	)
	if err != nil {
		return fmt.Errorf("upsert backup_config: %w", err)
	}
	logger.Info("backup settings saved",
		"enabled", s.Enabled, "schedule", s.Schedule,
		"timezone", s.Timezone, "retain_days", s.RetainDays)
	return nil
}
