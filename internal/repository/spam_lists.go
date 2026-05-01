package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// SpamListEntry is a single allow/block list row scoped to a domain.
// Rows are immutable: callers add or delete, never update in place. This
// matches how Rspamd consumes the underlying multimap files (rebuild on
// change) and keeps the table append-only for audit purposes.
type SpamListEntry struct {
	ID        string    `json:"id"`
	DomainID  string    `json:"domain_id"`
	Kind      string    `json:"kind"`  // 'allow' | 'block'
	Scope     string    `json:"scope"` // 'email' | 'domain'
	Pattern   string    `json:"pattern"`
	CreatedAt time.Time `json:"created_at"`
}

// SpamListCreate holds fields for creating a spam-list entry. Pattern is
// expected to be normalised (lowercased, trimmed) by the caller.
type SpamListCreate struct {
	DomainID string
	Kind     string
	Scope    string
	Pattern  string
}

// SpamListRepo handles per-domain allow/block list CRUD operations.
type SpamListRepo struct {
	db *pgxpool.Pool
}

// NewSpamListRepo creates a new spam-list repository.
func NewSpamListRepo(db *pgxpool.Pool) *SpamListRepo {
	return &SpamListRepo{db: db}
}

const spamListCols = `id, domain_id, kind, scope, pattern, created_at`

// Create inserts a new spam-list entry. Returns the inserted row, or an
// error if the (domain_id, kind, scope, pattern) tuple already exists
// (UNIQUE constraint).
func (r *SpamListRepo) Create(ctx context.Context, input SpamListCreate) (*SpamListEntry, error) {
	e := &SpamListEntry{
		ID:        types.NewUUIDv7(),
		DomainID:  input.DomainID,
		Kind:      input.Kind,
		Scope:     input.Scope,
		Pattern:   input.Pattern,
		CreatedAt: time.Now().UTC(),
	}

	_, err := r.db.Exec(ctx,
		`INSERT INTO domain_spam_lists (id, domain_id, kind, scope, pattern, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		e.ID, e.DomainID, e.Kind, e.Scope, e.Pattern, e.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert spam list entry: %w", err)
	}
	return e, nil
}

// GetByID fetches a spam-list entry by its UUID.
func (r *SpamListRepo) GetByID(ctx context.Context, id string) (*SpamListEntry, error) {
	e := &SpamListEntry{}
	err := r.db.QueryRow(ctx,
		`SELECT `+spamListCols+` FROM domain_spam_lists WHERE id = $1`, id,
	).Scan(&e.ID, &e.DomainID, &e.Kind, &e.Scope, &e.Pattern, &e.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get spam list entry: %w", err)
	}
	return e, nil
}

// ListByDomain returns all spam-list entries for a domain. If kindFilter is
// non-nil, only rows matching that kind ('allow' or 'block') are returned.
// Ordered by created_at DESC for stable UI display.
func (r *SpamListRepo) ListByDomain(ctx context.Context, domainID string, kindFilter *string) ([]SpamListEntry, error) {
	query := `SELECT ` + spamListCols + ` FROM domain_spam_lists WHERE domain_id = $1`
	args := []any{domainID}
	if kindFilter != nil {
		query += ` AND kind = $2`
		args = append(args, *kindFilter)
	}
	query += ` ORDER BY created_at DESC`

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list spam list entries: %w", err)
	}
	defer rows.Close()

	var out []SpamListEntry
	for rows.Next() {
		var e SpamListEntry
		if err := rows.Scan(&e.ID, &e.DomainID, &e.Kind, &e.Scope, &e.Pattern, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan spam list entry: %w", err)
		}
		out = append(out, e)
	}
	return out, nil
}

// Delete removes a single spam-list entry. Returns false if not found.
func (r *SpamListRepo) Delete(ctx context.Context, id string) (bool, error) {
	result, err := r.db.Exec(ctx, `DELETE FROM domain_spam_lists WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete spam list entry: %w", err)
	}
	return result.RowsAffected() > 0, nil
}
