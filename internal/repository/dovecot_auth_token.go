package repository

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/types"
)

// DovecotAuthTokenRepo mints and revokes short-lived Dovecot auth tokens — the
// credential a server-side feature uses to authenticate to Dovecot AS a target
// mailbox (the native IMAP importer; later admin impersonation). The Dovecot
// passdb in dovecot-sql.conf.ext validates these against this table. See
// migration 000023.
type DovecotAuthTokenRepo struct {
	db *pgxpool.Pool
}

// NewDovecotAuthTokenRepo creates the repo.
func NewDovecotAuthTokenRepo(db *pgxpool.Pool) *DovecotAuthTokenRepo {
	return &DovecotAuthTokenRepo{db: db}
}

// MintedToken is a freshly minted token: the row id (to revoke) and the
// PLAINTEXT password (used once to authenticate, never stored in plaintext).
type MintedToken struct {
	ID        string
	Password  string
	ExpiresAt time.Time
}

// Mint creates a token for targetUser valid for ttl. The plaintext password is
// returned only here; the table stores an argon2id hash (same scheme as
// mailboxes.password_hash, so the existing ARGON2ID passdb verifies it).
func (r *DovecotAuthTokenRepo) Mint(ctx context.Context, targetUser, purpose string, ttl time.Duration) (*MintedToken, error) {
	pw, err := randomPassword()
	if err != nil {
		return nil, err
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return nil, fmt.Errorf("hash auth token: %w", err)
	}

	id := types.NewUUIDv7()
	expires := time.Now().UTC().Add(ttl)
	_, err = r.db.Exec(ctx,
		`INSERT INTO dovecot_auth_tokens (id, target_user, password_hash, purpose, expires_at)
		 VALUES ($1, $2, $3, $4, $5)`,
		id, targetUser, hash, purpose, expires,
	)
	if err != nil {
		return nil, fmt.Errorf("insert auth token: %w", err)
	}
	return &MintedToken{ID: id, Password: pw, ExpiresAt: expires}, nil
}

// Revoke deletes a token by id (best-effort cleanup once the session is done).
func (r *DovecotAuthTokenRepo) Revoke(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx, `DELETE FROM dovecot_auth_tokens WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("revoke auth token: %w", err)
	}
	return nil
}

// PruneExpired removes tokens past their expiry. A safety net in case a session
// crashes before it revokes; the passdb already ignores expired rows.
func (r *DovecotAuthTokenRepo) PruneExpired(ctx context.Context) (int64, error) {
	tag, err := r.db.Exec(ctx, `DELETE FROM dovecot_auth_tokens WHERE expires_at < NOW()`)
	if err != nil {
		return 0, fmt.Errorf("prune auth tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// randomPassword returns a 48-char hex secret (24 random bytes).
func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate token password: %w", err)
	}
	return hex.EncodeToString(b), nil
}
