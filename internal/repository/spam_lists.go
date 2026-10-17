package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// Spam-list entry kinds. A DMARC exception (#265) lets one sender domain
// through DMARC enforcement for this recipient domain, but only from Network.
const (
	SpamListAllow          = "allow"
	SpamListBlock          = "block"
	SpamListDMARCException = "dmarc_exception"
)

// SpamListEntry is a single allow/block list row scoped to a domain.
// Rows are immutable: callers add or delete, never update in place. This
// matches how Rspamd consumes the underlying multimap files (rebuild on
// change) and keeps the table append-only for audit purposes.
type SpamListEntry struct {
	ID        string    `json:"id"`
	DomainID  string    `json:"domain_id"`
	Kind      string    `json:"kind"`  // 'allow' | 'block' | 'dmarc_exception'
	Scope     string    `json:"scope"` // 'email' | 'domain'
	Pattern   string    `json:"pattern"`
	Network   *string   `json:"network,omitempty"` // dmarc_exception only: IP, CIDR or hostname
	CreatedAt time.Time `json:"created_at"`
}

// SpamListCreate holds fields for creating a spam-list entry. Pattern is
// expected to be normalised (lowercased, trimmed) by the caller.
type SpamListCreate struct {
	DomainID string
	Kind     string
	Scope    string
	Pattern  string
	Network  string // required for dmarc_exception, empty otherwise
}

// SpamListRepo handles per-domain allow/block list CRUD operations.
type SpamListRepo struct {
	db *pgxpool.Pool
}

// NewSpamListRepo creates a new spam-list repository.
func NewSpamListRepo(db *pgxpool.Pool) *SpamListRepo {
	return &SpamListRepo{db: db}
}

const spamListCols = `id, domain_id, kind, scope, pattern, network, created_at`

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
	if input.Network != "" {
		n := input.Network
		e.Network = &n
	}

	_, err := r.db.Exec(ctx,
		`INSERT INTO domain_spam_lists (id, domain_id, kind, scope, pattern, network, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		e.ID, e.DomainID, e.Kind, e.Scope, e.Pattern, e.Network, e.CreatedAt,
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
	).Scan(&e.ID, &e.DomainID, &e.Kind, &e.Scope, &e.Pattern, &e.Network, &e.CreatedAt)
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
		if err := rows.Scan(&e.ID, &e.DomainID, &e.Kind, &e.Scope, &e.Pattern, &e.Network, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan spam list entry: %w", err)
		}
		out = append(out, e)
	}
	return out, nil
}

// ListAll returns every spam-list entry with the recipient domain name
// joined in. Used by the rspamd config regenerator to render the four
// per-recipient-domain allow/block map files in a single pass.
func (r *SpamListRepo) ListAll(ctx context.Context) ([]SpamListJoined, error) {
	q := `SELECT s.id, s.domain_id, d.name, s.kind, s.scope, s.pattern, s.network, s.created_at
	        FROM domain_spam_lists s
	        JOIN domains d ON d.id = s.domain_id
	       ORDER BY d.name, s.kind, s.scope, s.pattern, s.network`
	rows, err := r.db.Query(ctx, q)
	if err != nil && isUndefinedColumn(err) {
		// The network column arrives with migration 000026, which the new
		// api applies at start-up. The orchestrator can render before that
		// during an update; read the lists without it rather than failing
		// the render (there can be no exceptions before the column exists).
		q = `SELECT s.id, s.domain_id, d.name, s.kind, s.scope, s.pattern, NULL::text, s.created_at
		       FROM domain_spam_lists s
		       JOIN domains d ON d.id = s.domain_id
		      ORDER BY d.name, s.kind, s.scope, s.pattern`
		rows, err = r.db.Query(ctx, q)
	}
	if err != nil {
		return nil, fmt.Errorf("list all spam list entries: %w", err)
	}
	defer rows.Close()

	var out []SpamListJoined
	for rows.Next() {
		var e SpamListJoined
		var network *string
		if err := rows.Scan(&e.ID, &e.DomainID, &e.DomainName, &e.Kind, &e.Scope, &e.Pattern, &network, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan spam list join: %w", err)
		}
		if network != nil {
			e.Network = *network
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// isUndefinedColumn reports a Postgres undefined_column error (SQLSTATE 42703).
func isUndefinedColumn(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42703"
}

// SpamListJoined is a SpamListEntry annotated with the recipient domain
// name. Returned by ListAll for downstream multimap-file generation.
type SpamListJoined struct {
	ID         string
	DomainID   string
	DomainName string
	Kind       string
	Scope      string
	Pattern    string
	Network    string // dmarc_exception only
	CreatedAt  time.Time
}

// Delete removes a single spam-list entry. Returns false if not found.
// Delete removes a spam-list entry by id. allowedDomainIDs is a defense-in-depth
// domain guard (R5): nil = unrestricted; a non-nil slice restricts the delete to
// entries whose domain_id is in the set, so a handler-layer scope bug can't
// remove another tenant's filtering rule. Returns false if nothing matched.
func (r *SpamListRepo) Delete(ctx context.Context, id string, allowedDomainIDs []string) (bool, error) {
	q := `DELETE FROM domain_spam_lists WHERE id = $1`
	args := []any{id}
	if allowedDomainIDs != nil {
		q += ` AND domain_id = ANY($2)`
		args = append(args, allowedDomainIDs)
	}
	result, err := r.db.Exec(ctx, q, args...)
	if err != nil {
		return false, fmt.Errorf("delete spam list entry: %w", err)
	}
	return result.RowsAffected() > 0, nil
}
