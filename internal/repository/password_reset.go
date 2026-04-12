package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// PasswordResetToken represents a row in password_reset_tokens.
type PasswordResetToken struct {
	ID        string     `json:"id"`
	AdminID   string     `json:"admin_id"`
	TokenHash string     `json:"-"`
	ExpiresAt time.Time  `json:"expires_at"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// PasswordResetRepo manages password reset tokens.
type PasswordResetRepo struct {
	db *pgxpool.Pool
}

// NewPasswordResetRepo creates a new repository.
func NewPasswordResetRepo(db *pgxpool.Pool) *PasswordResetRepo {
	return &PasswordResetRepo{db: db}
}

// Create stores a new password reset token. The caller is responsible for
// hashing the raw token with SHA-256 before passing it here.
func (r *PasswordResetRepo) Create(ctx context.Context, adminID, tokenHash string, ttl time.Duration) (*PasswordResetToken, error) {
	id := types.NewUUIDv7()
	expiresAt := time.Now().UTC().Add(ttl)

	_, err := r.db.Exec(ctx,
		`INSERT INTO password_reset_tokens (id, admin_id, token_hash, expires_at)
		 VALUES ($1, $2, $3, $4)`,
		id, adminID, tokenHash, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert password reset token: %w", err)
	}

	return &PasswordResetToken{
		ID:        id,
		AdminID:   adminID,
		TokenHash: tokenHash,
		ExpiresAt: expiresAt,
		CreatedAt: time.Now().UTC(),
	}, nil
}

// FindByHash looks up an unused, non-expired token by its SHA-256 hash.
func (r *PasswordResetRepo) FindByHash(ctx context.Context, tokenHash string) (*PasswordResetToken, error) {
	var t PasswordResetToken
	err := r.db.QueryRow(ctx,
		`SELECT id, admin_id, token_hash, expires_at, used_at, created_at
		 FROM password_reset_tokens
		 WHERE token_hash = $1 AND used_at IS NULL AND expires_at > NOW()`,
		tokenHash,
	).Scan(&t.ID, &t.AdminID, &t.TokenHash, &t.ExpiresAt, &t.UsedAt, &t.CreatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("find password reset token: %w", err)
	}
	return &t, nil
}

// MarkUsed marks a token as used so it cannot be reused.
func (r *PasswordResetRepo) MarkUsed(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE password_reset_tokens SET used_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return fmt.Errorf("mark token used: %w", err)
	}
	return nil
}

// InvalidateForAdmin marks all outstanding tokens for an admin as used
// (e.g. after a successful password change).
func (r *PasswordResetRepo) InvalidateForAdmin(ctx context.Context, adminID string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE password_reset_tokens SET used_at = NOW()
		 WHERE admin_id = $1 AND used_at IS NULL`,
		adminID,
	)
	if err != nil {
		return fmt.Errorf("invalidate tokens for admin: %w", err)
	}
	return nil
}

// CleanExpired removes tokens that expired more than 24 hours ago.
func (r *PasswordResetRepo) CleanExpired(ctx context.Context) (int64, error) {
	result, err := r.db.Exec(ctx,
		`DELETE FROM password_reset_tokens
		 WHERE expires_at < NOW() - INTERVAL '24 hours'`)
	if err != nil {
		return 0, fmt.Errorf("clean expired reset tokens: %w", err)
	}
	return result.RowsAffected(), nil
}
