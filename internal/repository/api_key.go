package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// APIKey represents a stored API key (hash only — raw key is never persisted).
type APIKey struct {
	ID              string     `json:"id"`
	AdminID         string     `json:"admin_id"`
	Name            string     `json:"name"`
	KeyPrefix       string     `json:"key_prefix"`
	ScopedDomainIDs []string   `json:"scoped_domain_ids,omitempty"`
	RateLimit       int        `json:"rate_limit"`
	Active          bool       `json:"active"`
	ExpiresAt       *time.Time `json:"expires_at,omitempty"`
	LastUsedAt      *time.Time `json:"last_used_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

// APIKeyCreate holds fields for creating an API key.
type APIKeyCreate struct {
	AdminID         string
	Name            string
	KeyHash         string
	KeyPrefix       string
	ScopedDomainIDs []string
	RateLimit       int
	ExpiresAt       *time.Time
}

// APIKeyRepo handles API key CRUD operations.
type APIKeyRepo struct {
	db *pgxpool.Pool
}

// NewAPIKeyRepo creates a new API key repository.
func NewAPIKeyRepo(db *pgxpool.Pool) *APIKeyRepo {
	return &APIKeyRepo{db: db}
}

// Create inserts a new API key.
func (r *APIKeyRepo) Create(ctx context.Context, input APIKeyCreate) (*APIKey, error) {
	id := types.NewUUIDv7()
	rateLimit := input.RateLimit
	if rateLimit == 0 {
		rateLimit = 60
	}

	_, err := r.db.Exec(ctx,
		`INSERT INTO api_keys (id, admin_id, name, key_hash, key_prefix, scoped_domain_ids, rate_limit, active, expires_at, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, true, $8, NOW())`,
		id, input.AdminID, input.Name, input.KeyHash, input.KeyPrefix, input.ScopedDomainIDs, rateLimit, input.ExpiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert api key: %w", err)
	}
	return r.GetByID(ctx, id)
}

// GetByID fetches an API key by UUID.
func (r *APIKeyRepo) GetByID(ctx context.Context, id string) (*APIKey, error) {
	k := &APIKey{}
	err := r.db.QueryRow(ctx,
		`SELECT id, admin_id, name, key_prefix, scoped_domain_ids, rate_limit, active, expires_at, last_used_at, created_at
		 FROM api_keys WHERE id = $1`, id,
	).Scan(&k.ID, &k.AdminID, &k.Name, &k.KeyPrefix, &k.ScopedDomainIDs, &k.RateLimit, &k.Active, &k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get api key: %w", err)
	}
	return k, nil
}

// GetByHash fetches an active, non-expired API key by its SHA-256 hash.
func (r *APIKeyRepo) GetByHash(ctx context.Context, keyHash string) (*APIKey, error) {
	k := &APIKey{}
	err := r.db.QueryRow(ctx,
		`SELECT id, admin_id, name, key_prefix, scoped_domain_ids, rate_limit, active, expires_at, last_used_at, created_at
		 FROM api_keys
		 WHERE key_hash = $1 AND active = true AND (expires_at IS NULL OR expires_at > NOW())`, keyHash,
	).Scan(&k.ID, &k.AdminID, &k.Name, &k.KeyPrefix, &k.ScopedDomainIDs, &k.RateLimit, &k.Active, &k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get api key by hash: %w", err)
	}
	return k, nil
}

// ListByAdmin returns all API keys for an admin.
func (r *APIKeyRepo) ListByAdmin(ctx context.Context, adminID string) ([]APIKey, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, admin_id, name, key_prefix, scoped_domain_ids, rate_limit, active, expires_at, last_used_at, created_at
		 FROM api_keys WHERE admin_id = $1 ORDER BY created_at DESC`, adminID)
	if err != nil {
		return nil, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.AdminID, &k.Name, &k.KeyPrefix, &k.ScopedDomainIDs, &k.RateLimit, &k.Active, &k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// ListAll returns all API keys (for super_admin listing).
func (r *APIKeyRepo) ListAll(ctx context.Context) ([]APIKey, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, admin_id, name, key_prefix, scoped_domain_ids, rate_limit, active, expires_at, last_used_at, created_at
		 FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list all api keys: %w", err)
	}
	defer rows.Close()

	var keys []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.AdminID, &k.Name, &k.KeyPrefix, &k.ScopedDomainIDs, &k.RateLimit, &k.Active, &k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan api key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// Revoke deactivates an API key.
func (r *APIKeyRepo) Revoke(ctx context.Context, id string) (bool, error) {
	result, err := r.db.Exec(ctx,
		`UPDATE api_keys SET active = false WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("revoke api key: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

// Delete permanently removes an API key.
func (r *APIKeyRepo) Delete(ctx context.Context, id string) (bool, error) {
	result, err := r.db.Exec(ctx, `DELETE FROM api_keys WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete api key: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

// TouchLastUsed updates the last_used_at timestamp. Fire-and-forget.
func (r *APIKeyRepo) TouchLastUsed(ctx context.Context, id string) {
	r.db.Exec(ctx, `UPDATE api_keys SET last_used_at = NOW() WHERE id = $1`, id)
}
