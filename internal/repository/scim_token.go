package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// SCIMToken represents a stored SCIM provisioning bearer token (hash only — the
// raw token is shown once at creation and never persisted). Migration 000021.
type SCIMToken struct {
	ID          string     `json:"id"`
	TokenPrefix string     `json:"token_prefix"`
	Active      bool       `json:"active"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time `json:"last_used_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// SCIMTokenCreate holds fields for creating a SCIM token.
type SCIMTokenCreate struct {
	TokenHash   string
	TokenPrefix string
	ExpiresAt   *time.Time
}

// SCIMTokenRepo handles SCIM token CRUD operations.
type SCIMTokenRepo struct {
	db *pgxpool.Pool
}

// NewSCIMTokenRepo creates a new SCIM token repository.
func NewSCIMTokenRepo(db *pgxpool.Pool) *SCIMTokenRepo {
	return &SCIMTokenRepo{db: db}
}

// Create inserts a new SCIM token (storing only the hash) and returns the
// persisted row (without the hash).
func (r *SCIMTokenRepo) Create(ctx context.Context, input SCIMTokenCreate) (*SCIMToken, error) {
	id := types.NewUUIDv7()
	_, err := r.db.Exec(ctx,
		`INSERT INTO scim_tokens (id, token_hash, token_prefix, active, expires_at, created_at)
		 VALUES ($1, $2, $3, true, $4, NOW())`,
		id, input.TokenHash, input.TokenPrefix, input.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert scim token: %w", err)
	}
	return r.GetByID(ctx, id)
}

// GetByID fetches a SCIM token by UUID (hash never returned).
func (r *SCIMTokenRepo) GetByID(ctx context.Context, id string) (*SCIMToken, error) {
	t := &SCIMToken{}
	err := r.db.QueryRow(ctx,
		`SELECT id, token_prefix, active, expires_at, last_used_at, created_at
		 FROM scim_tokens WHERE id = $1`, id,
	).Scan(&t.ID, &t.TokenPrefix, &t.Active, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get scim token by id: %w", err)
	}
	return t, nil
}

// GetByHash returns the active, non-expired token matching the SHA-256 hash, or
// nil if there is no usable match. The auth middleware's lookup path.
func (r *SCIMTokenRepo) GetByHash(ctx context.Context, tokenHash string) (*SCIMToken, error) {
	t := &SCIMToken{}
	err := r.db.QueryRow(ctx,
		`SELECT id, token_prefix, active, expires_at, last_used_at, created_at
		 FROM scim_tokens
		 WHERE token_hash = $1 AND active = true AND (expires_at IS NULL OR expires_at > NOW())`, tokenHash,
	).Scan(&t.ID, &t.TokenPrefix, &t.Active, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get scim token by hash: %w", err)
	}
	return t, nil
}

// ListAll returns all SCIM tokens (active and revoked), newest first.
func (r *SCIMTokenRepo) ListAll(ctx context.Context) ([]SCIMToken, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, token_prefix, active, expires_at, last_used_at, created_at
		 FROM scim_tokens ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list scim tokens: %w", err)
	}
	defer rows.Close()

	var out []SCIMToken
	for rows.Next() {
		var t SCIMToken
		if err := rows.Scan(&t.ID, &t.TokenPrefix, &t.Active, &t.ExpiresAt, &t.LastUsedAt, &t.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan scim token: %w", err)
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// Revoke deactivates a token (active=false). Returns whether a row was changed.
func (r *SCIMTokenRepo) Revoke(ctx context.Context, id string) (bool, error) {
	result, err := r.db.Exec(ctx, `UPDATE scim_tokens SET active = false WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("revoke scim token: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

// TouchLastUsed stamps last_used_at (fire-and-forget; errors are non-fatal).
func (r *SCIMTokenRepo) TouchLastUsed(ctx context.Context, id string) {
	_, _ = r.db.Exec(ctx, `UPDATE scim_tokens SET last_used_at = NOW() WHERE id = $1`, id)
}
