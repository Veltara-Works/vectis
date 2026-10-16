package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// IPWarmup represents an IP warmup tracking record.
type IPWarmup struct {
	ID            string    `json:"id"`
	IPAddress     string    `json:"ip_address"`
	Label         string    `json:"label,omitempty"`
	WarmupStarted time.Time `json:"warmup_started"`
	WarmupDay     int       `json:"warmup_day"`
	DailyLimit    int       `json:"daily_limit"`
	DailySent     int       `json:"daily_sent"`
	LastResetAt   time.Time `json:"last_reset_at"`
	Active        bool      `json:"active"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// IPWarmupRepo handles IP warmup tracking.
type IPWarmupRepo struct {
	db *pgxpool.Pool
}

// NewIPWarmupRepo creates a new IP warmup repository.
func NewIPWarmupRepo(db *pgxpool.Pool) *IPWarmupRepo {
	return &IPWarmupRepo{db: db}
}

// Create adds a new IP to the warmup schedule.
func (r *IPWarmupRepo) Create(ctx context.Context, ipAddress, label string) (*IPWarmup, error) {
	id := types.NewUUIDv7()
	now := time.Now().UTC()

	_, err := r.db.Exec(ctx,
		`INSERT INTO ip_warmup (id, ip_address, label, warmup_started, warmup_day, daily_limit, daily_sent, last_reset_at, active, created_at, updated_at)
		 VALUES ($1, $2::inet, $3, $4, 1, 50, 0, $4, true, $4, $4)`,
		id, ipAddress, label, now,
	)
	if err != nil {
		return nil, fmt.Errorf("create ip warmup: %w", err)
	}

	return &IPWarmup{
		ID: id, IPAddress: ipAddress, Label: label,
		WarmupStarted: now, WarmupDay: 1, DailyLimit: 50,
		DailySent: 0, LastResetAt: now, Active: true,
		CreatedAt: now, UpdatedAt: now,
	}, nil
}

// List returns all IP warmup entries.
func (r *IPWarmupRepo) List(ctx context.Context) ([]IPWarmup, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, ip_address::text, label, warmup_started, warmup_day, daily_limit, daily_sent, last_reset_at, active, created_at, updated_at
		 FROM ip_warmup ORDER BY created_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list ip warmup: %w", err)
	}
	defer rows.Close()

	var entries []IPWarmup
	for rows.Next() {
		var e IPWarmup
		if err := rows.Scan(&e.ID, &e.IPAddress, &e.Label, &e.WarmupStarted, &e.WarmupDay,
			&e.DailyLimit, &e.DailySent, &e.LastResetAt, &e.Active, &e.CreatedAt, &e.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan ip warmup: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// GetByIP retrieves an IP warmup entry by IP address.
func (r *IPWarmupRepo) GetByIP(ctx context.Context, ipAddress string) (*IPWarmup, error) {
	var e IPWarmup
	err := r.db.QueryRow(ctx,
		`SELECT id, ip_address::text, label, warmup_started, warmup_day, daily_limit, daily_sent, last_reset_at, active, created_at, updated_at
		 FROM ip_warmup WHERE ip_address = $1::inet`, ipAddress,
	).Scan(&e.ID, &e.IPAddress, &e.Label, &e.WarmupStarted, &e.WarmupDay,
		&e.DailyLimit, &e.DailySent, &e.LastResetAt, &e.Active, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get ip warmup: %w", err)
	}
	return &e, nil
}

// GetActive returns the active warmup entry, or nil when no warmup is
// running. A server sends from one IP, so at most one entry is active; if
// older data holds several, the oldest wins.
func (r *IPWarmupRepo) GetActive(ctx context.Context) (*IPWarmup, error) {
	var e IPWarmup
	err := r.db.QueryRow(ctx,
		`SELECT id, ip_address::text, label, warmup_started, warmup_day, daily_limit, daily_sent, last_reset_at, active, created_at, updated_at
		 FROM ip_warmup WHERE active ORDER BY created_at ASC LIMIT 1`,
	).Scan(&e.ID, &e.IPAddress, &e.Label, &e.WarmupStarted, &e.WarmupDay,
		&e.DailyLimit, &e.DailySent, &e.LastResetAt, &e.Active, &e.CreatedAt, &e.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get active ip warmup: %w", err)
	}
	return &e, nil
}

// warmupCreateLock is the transaction-scoped advisory lock key that
// serialises starting a warmup, so two requests can't both find no active
// warmup and both start one. ("WARM"; the orchestrator's lock is 1.)
const warmupCreateLock int64 = 0x5741524D

// CreateIfNoneActive starts a warmup for ipAddress unless one is already
// active, atomically. It returns the new entry, or nil and the active entry.
func (r *IPWarmupRepo) CreateIfNoneActive(ctx context.Context, ipAddress, label string) (*IPWarmup, *IPWarmup, error) {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("begin ip warmup create: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // no-op after Commit

	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, warmupCreateLock); err != nil {
		return nil, nil, fmt.Errorf("lock ip warmup create: %w", err)
	}
	var a IPWarmup
	err = tx.QueryRow(ctx,
		`SELECT id, ip_address::text, label, warmup_started, warmup_day, daily_limit, daily_sent, last_reset_at, active, created_at, updated_at
		 FROM ip_warmup WHERE active ORDER BY created_at ASC LIMIT 1`,
	).Scan(&a.ID, &a.IPAddress, &a.Label, &a.WarmupStarted, &a.WarmupDay,
		&a.DailyLimit, &a.DailySent, &a.LastResetAt, &a.Active, &a.CreatedAt, &a.UpdatedAt)
	switch {
	case err == nil:
		return nil, &a, nil
	case err != pgx.ErrNoRows:
		return nil, nil, fmt.Errorf("check active ip warmup: %w", err)
	}

	id := types.NewUUIDv7()
	now := time.Now().UTC()
	if _, err := tx.Exec(ctx,
		`INSERT INTO ip_warmup (id, ip_address, label, warmup_started, warmup_day, daily_limit, daily_sent, last_reset_at, active, created_at, updated_at)
		 VALUES ($1, $2::inet, $3, $4, 1, $5, 0, $4, true, $4, $4)`,
		id, ipAddress, label, now, WarmupSchedule(1),
	); err != nil {
		return nil, nil, fmt.Errorf("create ip warmup: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, fmt.Errorf("commit ip warmup create: %w", err)
	}
	return &IPWarmup{
		ID: id, IPAddress: ipAddress, Label: label,
		WarmupStarted: now, WarmupDay: 1, DailyLimit: WarmupSchedule(1),
		DailySent: 0, LastResetAt: now, Active: true,
		CreatedAt: now, UpdatedAt: now,
	}, nil, nil
}

// Reserve adds n to the active entry's daily_sent if that keeps it within
// daily_limit and the entry's day is still current (last_reset_at after
// dayStartedAfter), in a single UPDATE so concurrent sends can't overshoot and
// can't be charged to a day that has already ended. It returns the entry
// after the update and true, or the entry unchanged and false when n doesn't
// fit or the day is due to reset. A nil entry means no warmup is active.
func (r *IPWarmupRepo) Reserve(ctx context.Context, n int, dayStartedAfter time.Time) (*IPWarmup, bool, error) {
	var e IPWarmup
	err := r.db.QueryRow(ctx,
		`UPDATE ip_warmup SET daily_sent = daily_sent + $1, updated_at = NOW()
		 WHERE id = (SELECT id FROM ip_warmup WHERE active ORDER BY created_at ASC LIMIT 1)
		   AND daily_sent + $1 <= daily_limit
		   AND last_reset_at > $2
		 RETURNING id, ip_address::text, label, warmup_started, warmup_day, daily_limit, daily_sent, last_reset_at, active, created_at, updated_at`,
		n, dayStartedAfter,
	).Scan(&e.ID, &e.IPAddress, &e.Label, &e.WarmupStarted, &e.WarmupDay,
		&e.DailyLimit, &e.DailySent, &e.LastResetAt, &e.Active, &e.CreatedAt, &e.UpdatedAt)
	if err == nil {
		return &e, true, nil
	}
	if err != pgx.ErrNoRows {
		return nil, false, fmt.Errorf("reserve ip warmup sends: %w", err)
	}
	// Nothing updated: either no warmup is active, or n doesn't fit today.
	active, err := r.GetActive(ctx)
	if err != nil {
		return nil, false, err
	}
	return active, false, nil
}

// Release gives back n reserved sends (a message that was reserved but then
// failed to send), never taking daily_sent below zero. dayStart is the
// reservation's last_reset_at: if the day has reset since, there is nothing to
// give back, and today's count is left alone.
func (r *IPWarmupRepo) Release(ctx context.Context, id string, n int, dayStart time.Time) error {
	_, err := r.db.Exec(ctx,
		`UPDATE ip_warmup SET daily_sent = GREATEST(daily_sent - $1, 0), updated_at = NOW()
		 WHERE id = $2 AND last_reset_at = $3`, n, id, dayStart)
	if err != nil {
		return fmt.Errorf("release ip warmup sends: %w", err)
	}
	return nil
}

// AdvanceDay resets daily_sent and advances the warmup day with a new daily
// limit, if the entry is still on the day that started at prevReset (so two
// advances racing can't skip a day). resetAt becomes last_reset_at: the
// manager passes the scheduled boundary rather than the time it noticed, so
// the day doesn't drift later. It reports whether the entry was advanced.
func (r *IPWarmupRepo) AdvanceDay(ctx context.Context, id string, prevReset time.Time, newDay, newLimit int, resetAt time.Time) (bool, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE ip_warmup SET warmup_day = $1, daily_limit = $2, daily_sent = 0, last_reset_at = $3, updated_at = NOW()
		 WHERE id = $4 AND last_reset_at = $5`,
		newDay, newLimit, resetAt, id, prevReset,
	)
	if err != nil {
		return false, fmt.Errorf("advance ip warmup day: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// Deactivate marks an IP warmup as inactive (warmup complete or manually stopped).
func (r *IPWarmupRepo) Deactivate(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE ip_warmup SET active = false, updated_at = NOW() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("deactivate ip warmup: %w", err)
	}
	return nil
}

// Delete removes an IP warmup entry.
func (r *IPWarmupRepo) Delete(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM ip_warmup WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete ip warmup: %w", err)
	}
	return nil
}

// WarmupSchedule returns the recommended daily sending limit for a given warmup day.
// Standard 30-day warmup ramp: starts at 50, doubles every 2 days, capped at target.
func WarmupSchedule(day int) int {
	schedule := []int{
		50, 50, // days 1-2
		100, 100, // days 3-4
		200, 200, // days 5-6
		500, 500, // days 7-8
		1000, 1000, // days 9-10
		2000, 2000, // days 11-12
		5000, 5000, // days 13-14
		10000, 10000, // days 15-16
		20000, 20000, // days 17-18
		40000, 40000, // days 19-20
		60000, 60000, // days 21-22
		80000, 80000, // days 23-24
		100000, 100000, // days 25-26
		150000, 150000, // days 27-28
		200000, 200000, // days 29-30
	}
	if day <= 0 {
		return schedule[0]
	}
	if day > len(schedule) {
		return schedule[len(schedule)-1] // fully warmed
	}
	return schedule[day-1]
}
