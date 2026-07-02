package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// AbuseEvent represents a detected abuse event.
type AbuseEvent struct {
	ID         string          `json:"id"`
	DomainID   *string         `json:"domain_id,omitempty"`
	MailboxID  *string         `json:"mailbox_id,omitempty"`
	EventType  string          `json:"event_type"`
	Severity   string          `json:"severity"`
	Details    json.RawMessage `json:"details,omitempty"`
	Action     *string         `json:"action,omitempty"`
	Resolved   bool            `json:"resolved"`
	ResolvedBy *string         `json:"resolved_by,omitempty"`
	ResolvedAt *time.Time      `json:"resolved_at,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

// AbuseRepo handles abuse event logging and mailbox suspension.
type AbuseRepo struct {
	db *pgxpool.Pool
}

// NewAbuseRepo creates a new abuse repository.
func NewAbuseRepo(db *pgxpool.Pool) *AbuseRepo {
	return &AbuseRepo{db: db}
}

// LogEvent records an abuse detection event.
func (r *AbuseRepo) LogEvent(ctx context.Context, domainID, mailboxID *string, eventType, severity string, details any, action *string) (string, error) {
	id := types.NewUUIDv7()
	var detailsJSON []byte
	if details != nil {
		var err error
		detailsJSON, err = json.Marshal(details)
		if err != nil {
			return "", fmt.Errorf("marshal abuse details: %w", err)
		}
	}

	_, err := r.db.Exec(ctx,
		`INSERT INTO abuse_events (id, domain_id, mailbox_id, event_type, severity, details, action, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())`,
		id, domainID, mailboxID, eventType, severity, detailsJSON, action,
	)
	if err != nil {
		return "", fmt.Errorf("insert abuse event: %w", err)
	}
	return id, nil
}

// SuspendMailbox sets the send_suspended flag on a mailbox.
func (r *AbuseRepo) SuspendMailbox(ctx context.Context, mailboxID, reason string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE mailboxes SET send_suspended = true, send_suspended_at = NOW(), send_suspended_reason = $1 WHERE id = $2`,
		reason, mailboxID,
	)
	if err != nil {
		return fmt.Errorf("suspend mailbox: %w", err)
	}
	return nil
}

// UnsuspendMailbox clears the send_suspended flag.
func (r *AbuseRepo) UnsuspendMailbox(ctx context.Context, mailboxID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE mailboxes SET send_suspended = false, send_suspended_at = NULL, send_suspended_reason = NULL WHERE id = $1`,
		mailboxID,
	)
	if err != nil {
		return fmt.Errorf("unsuspend mailbox: %w", err)
	}
	return nil
}

// IsMailboxSuspended returns true if the mailbox is suspended from sending.
func (r *AbuseRepo) IsMailboxSuspended(ctx context.Context, mailboxID string) (bool, string, error) {
	var suspended bool
	var reason *string
	err := r.db.QueryRow(ctx,
		`SELECT send_suspended, send_suspended_reason FROM mailboxes WHERE id = $1`, mailboxID,
	).Scan(&suspended, &reason)
	if err != nil {
		return false, "", fmt.Errorf("check mailbox suspension: %w", err)
	}
	reasonStr := ""
	if reason != nil {
		reasonStr = *reason
	}
	return suspended, reasonStr, nil
}

// ListUnresolved returns unresolved abuse events.
func (r *AbuseRepo) ListUnresolved(ctx context.Context, limit int) ([]AbuseEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(ctx,
		`SELECT id, domain_id, mailbox_id, event_type, severity, details, action, resolved, resolved_by, resolved_at, created_at
		 FROM abuse_events WHERE resolved = false ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list unresolved abuse events: %w", err)
	}
	defer rows.Close()
	return scanAbuseEvents(rows)
}

// ListRecent returns recent abuse events (resolved and unresolved).
func (r *AbuseRepo) ListRecent(ctx context.Context, limit int) ([]AbuseEvent, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(ctx,
		`SELECT id, domain_id, mailbox_id, event_type, severity, details, action, resolved, resolved_by, resolved_at, created_at
		 FROM abuse_events ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list recent abuse events: %w", err)
	}
	defer rows.Close()
	return scanAbuseEvents(rows)
}

// GetByID returns a single abuse event by id, or nil if not found. Used by the
// resolve handler to resolve the event's domain for scope enforcement (R2).
func (r *AbuseRepo) GetByID(ctx context.Context, id string) (*AbuseEvent, error) {
	var e AbuseEvent
	err := r.db.QueryRow(ctx,
		`SELECT id, domain_id, mailbox_id, event_type, severity, details, action, resolved, resolved_by, resolved_at, created_at
		 FROM abuse_events WHERE id = $1`, id,
	).Scan(&e.ID, &e.DomainID, &e.MailboxID, &e.EventType, &e.Severity, &e.Details, &e.Action, &e.Resolved, &e.ResolvedBy, &e.ResolvedAt, &e.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get abuse event: %w", err)
	}
	return &e, nil
}

// Resolve marks an abuse event as resolved.
func (r *AbuseRepo) Resolve(ctx context.Context, eventID, adminID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE abuse_events SET resolved = true, resolved_by = $1, resolved_at = NOW() WHERE id = $2`,
		adminID, eventID,
	)
	if err != nil {
		return fmt.Errorf("resolve abuse event: %w", err)
	}
	return nil
}

func scanAbuseEvents(rows interface{ Next() bool; Scan(dest ...any) error }) ([]AbuseEvent, error) {
	var events []AbuseEvent
	for rows.Next() {
		var e AbuseEvent
		if err := rows.Scan(&e.ID, &e.DomainID, &e.MailboxID, &e.EventType, &e.Severity, &e.Details, &e.Action, &e.Resolved, &e.ResolvedBy, &e.ResolvedAt, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan abuse event: %w", err)
		}
		events = append(events, e)
	}
	return events, nil
}
