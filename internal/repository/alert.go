package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// AlertEntry represents a row in the alert_history table.
type AlertEntry struct {
	ID         string     `json:"id"`
	Severity   string     `json:"severity"`
	Service    string     `json:"service"`
	Message    string     `json:"message"`
	DedupKey   string     `json:"dedup_key"`
	SentAt     time.Time  `json:"sent_at"`
	ResolvedAt *time.Time `json:"resolved_at,omitempty"`
}

// AlertRepo handles alert_history CRUD operations.
type AlertRepo struct {
	db *pgxpool.Pool
}

// NewAlertRepo creates a new alert repository.
func NewAlertRepo(db *pgxpool.Pool) *AlertRepo {
	return &AlertRepo{db: db}
}

// Log inserts a new alert into the alert_history table.
func (r *AlertRepo) Log(ctx context.Context, severity, service, message, dedupKey string) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO alert_history (id, severity, service, message, dedup_key, sent_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		types.NewUUIDv7(), severity, service, message, dedupKey, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert alert: %w", err)
	}
	return nil
}

// FindRecent returns the most recent alert matching the given dedup key
// sent within the specified duration. Returns nil if no recent alert exists.
func (r *AlertRepo) FindRecent(ctx context.Context, dedupKey string, within time.Duration) (*AlertEntry, error) {
	cutoff := time.Now().UTC().Add(-within)
	a := &AlertEntry{}
	err := r.db.QueryRow(ctx,
		`SELECT id, severity, service, message, dedup_key, sent_at, resolved_at
		 FROM alert_history
		 WHERE dedup_key = $1 AND sent_at > $2
		 ORDER BY sent_at DESC
		 LIMIT 1`,
		dedupKey, cutoff,
	).Scan(&a.ID, &a.Severity, &a.Service, &a.Message, &a.DedupKey, &a.SentAt, &a.ResolvedAt)

	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find recent alert: %w", err)
	}
	return a, nil
}

// Resolve marks all unresolved alerts with the given dedup key as resolved.
func (r *AlertRepo) Resolve(ctx context.Context, dedupKey string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE alert_history SET resolved_at = $1
		 WHERE dedup_key = $2 AND resolved_at IS NULL`,
		time.Now().UTC(), dedupKey,
	)
	if err != nil {
		return fmt.Errorf("resolve alert: %w", err)
	}
	return nil
}

// ListActive returns all unresolved alerts ordered by most recent first.
func (r *AlertRepo) ListActive(ctx context.Context) ([]AlertEntry, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, severity, service, message, dedup_key, sent_at, resolved_at
		 FROM alert_history
		 WHERE resolved_at IS NULL
		 ORDER BY sent_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list active alerts: %w", err)
	}
	defer rows.Close()

	var entries []AlertEntry
	for rows.Next() {
		var a AlertEntry
		if err := rows.Scan(&a.ID, &a.Severity, &a.Service, &a.Message, &a.DedupKey, &a.SentAt, &a.ResolvedAt); err != nil {
			return nil, fmt.Errorf("scan alert entry: %w", err)
		}
		entries = append(entries, a)
	}
	return entries, nil
}
