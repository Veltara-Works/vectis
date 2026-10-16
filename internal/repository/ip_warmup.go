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

// IncrementSent increments the daily_sent counter for an IP.
func (r *IPWarmupRepo) IncrementSent(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE ip_warmup SET daily_sent = daily_sent + 1, updated_at = NOW() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("increment ip warmup sent: %w", err)
	}
	return nil
}

// AdvanceDay resets daily_sent and advances the warmup day with a new daily limit.
func (r *IPWarmupRepo) AdvanceDay(ctx context.Context, id string, newDay, newLimit int) error {
	_, err := r.db.Exec(ctx,
		`UPDATE ip_warmup SET warmup_day = $1, daily_limit = $2, daily_sent = 0, last_reset_at = NOW(), updated_at = NOW() WHERE id = $3`,
		newDay, newLimit, id,
	)
	if err != nil {
		return fmt.Errorf("advance ip warmup day: %w", err)
	}
	return nil
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
