package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go"

	"github.com/Veltara-Works/vectis/internal/types"
)

// Session represents an active admin session.
type Session struct {
	ID        string    `json:"id"`
	AdminID   string    `json:"admin_id"`
	IPAddress string    `json:"ip_address,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionManager handles dual-stored sessions (Valkey + Postgres).
// Valkey is the authority for session validity (keyed by token_hash).
// Postgres is the authority for session inventory.
type SessionManager struct {
	db           *pgxpool.Pool
	vk           valkey.Client
	ttl          time.Duration
	cookieSecret []byte
}

// NewSessionManager creates a session manager.
func NewSessionManager(db *pgxpool.Pool, vk valkey.Client, ttlHours int, cookieSecret string) *SessionManager {
	return &SessionManager{
		db:           db,
		vk:           vk,
		ttl:          time.Duration(ttlHours) * time.Hour,
		cookieSecret: []byte(cookieSecret),
	}
}

// SignToken produces an HMAC-signed cookie value: "token.signature".
func (sm *SessionManager) SignToken(token string) string {
	mac := hmac.New(sha256.New, sm.cookieSecret)
	mac.Write([]byte(token))
	sig := hex.EncodeToString(mac.Sum(nil))
	return token + "." + sig
}

// VerifyAndExtractToken verifies the HMAC signature and returns the raw token.
// Returns ("", error) if the signature is invalid.
func (sm *SessionManager) VerifyAndExtractToken(signed string) (string, error) {
	parts := strings.SplitN(signed, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid signed token format")
	}
	token, sig := parts[0], parts[1]

	mac := hmac.New(sha256.New, sm.cookieSecret)
	mac.Write([]byte(token))
	expectedSig := hex.EncodeToString(mac.Sum(nil))

	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", fmt.Errorf("invalid token signature")
	}
	return token, nil
}

// CreateSession generates a new session for an admin, stores it in both
// Valkey and Postgres, and returns the raw token (to be set as HMAC-signed cookie).
func (sm *SessionManager) CreateSession(ctx context.Context, adminID, ipAddress, userAgent string) (token string, session *Session, err error) {
	// Generate 256-bit random token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}
	token = hex.EncodeToString(tokenBytes)

	// SHA-256 hash — used as the key in Valkey and stored in Postgres.
	// The raw token is only sent to the client (in the signed cookie).
	tokenHash := sha256Hash(token)

	sessionID := types.NewUUIDv7()
	now := time.Now().UTC()
	expiresAt := now.Add(sm.ttl)

	session = &Session{
		ID:        sessionID,
		AdminID:   adminID,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	// Store in Valkey (authority for validity). Key = token_hash, Value = sessionID:adminID.
	vkCmd := sm.vk.B().Set().Key(valkeySessionKey(tokenHash)).Value(sessionID + ":" + adminID).Ex(sm.ttl).Build()
	if err := sm.vk.Do(ctx, vkCmd).Error(); err != nil {
		return "", nil, fmt.Errorf("store session in valkey: %w", err)
	}

	// Store in Postgres (authority for inventory).
	var ipAddr any
	if ipAddress != "" {
		ipAddr = ipAddress
	}
	_, err = sm.db.Exec(ctx,
		`INSERT INTO sessions (id, admin_id, token_hash, ip_address, user_agent, created_at, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		sessionID, adminID, tokenHash, ipAddr, userAgent, now, expiresAt,
	)
	if err != nil {
		return "", nil, fmt.Errorf("store session in postgres: %w", err)
	}

	return token, session, nil
}

// ValidateSession checks if a session is valid by hashing the raw token and
// looking up the token_hash in Valkey. Returns (sessionID, adminID) if valid.
func (sm *SessionManager) ValidateSession(ctx context.Context, rawToken string) (sessionID, adminID string, err error) {
	tokenHash := sha256Hash(rawToken)
	cmd := sm.vk.B().Get().Key(valkeySessionKey(tokenHash)).Build()
	result, err := sm.vk.Do(ctx, cmd).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return "", "", fmt.Errorf("session expired or invalid")
		}
		return "", "", fmt.Errorf("validate session: %w", err)
	}
	// Value format: "sessionID:adminID"
	parts := strings.SplitN(result, ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("corrupt session data in valkey")
	}
	return parts[0], parts[1], nil
}

// DeleteSession removes a session from both Valkey and Postgres.
// Looks up the token_hash from Postgres to remove the Valkey key.
func (sm *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	// Look up the token_hash from Postgres so we can remove from Valkey.
	var tokenHash string
	err := sm.db.QueryRow(ctx, `SELECT token_hash FROM sessions WHERE id = $1`, sessionID).Scan(&tokenHash)
	if err == nil && tokenHash != "" {
		cmd := sm.vk.B().Del().Key(valkeySessionKey(tokenHash)).Build()
		sm.vk.Do(ctx, cmd)
	}

	// Remove from Postgres.
	_, err = sm.db.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	if err != nil {
		return fmt.Errorf("delete session from postgres: %w", err)
	}
	return nil
}

// DeleteSessionForAdmin removes a session only if it belongs to adminID. It
// returns (true, nil) when a matching session was deleted, and (false, nil)
// when no session with that ID is owned by adminID — letting the caller answer
// 404 without revealing whether the ID exists under another admin. This is the
// ownership-scoped form of DeleteSession: the revoke-a-session endpoint must
// not let one admin delete another admin's session by ID (IDOR).
func (sm *SessionManager) DeleteSessionForAdmin(ctx context.Context, sessionID, adminID string) (bool, error) {
	// Scope the token_hash lookup to the owning admin so a non-owned ID never
	// even surfaces a Valkey key to delete.
	var tokenHash string
	err := sm.db.QueryRow(ctx,
		`SELECT token_hash FROM sessions WHERE id = $1 AND admin_id = $2`,
		sessionID, adminID).Scan(&tokenHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil // unknown ID, or owned by a different admin
	}
	if err != nil {
		return false, fmt.Errorf("look up session for admin: %w", err)
	}

	if tokenHash != "" {
		cmd := sm.vk.B().Del().Key(valkeySessionKey(tokenHash)).Build()
		sm.vk.Do(ctx, cmd)
	}

	ct, err := sm.db.Exec(ctx,
		`DELETE FROM sessions WHERE id = $1 AND admin_id = $2`, sessionID, adminID)
	if err != nil {
		return false, fmt.Errorf("delete session from postgres: %w", err)
	}
	return ct.RowsAffected() > 0, nil
}

// DeleteAllSessions removes all sessions for an admin.
func (sm *SessionManager) DeleteAllSessions(ctx context.Context, adminID string) error {
	// Get all token hashes from Postgres.
	rows, err := sm.db.Query(ctx, `SELECT token_hash FROM sessions WHERE admin_id = $1`, adminID)
	if err != nil {
		return fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	var tokenHashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return fmt.Errorf("scan token_hash: %w", err)
		}
		tokenHashes = append(tokenHashes, hash)
	}

	// Delete from Valkey.
	for _, hash := range tokenHashes {
		cmd := sm.vk.B().Del().Key(valkeySessionKey(hash)).Build()
		sm.vk.Do(ctx, cmd)
	}

	// Delete from Postgres.
	_, err = sm.db.Exec(ctx, `DELETE FROM sessions WHERE admin_id = $1`, adminID)
	if err != nil {
		return fmt.Errorf("delete sessions from postgres: %w", err)
	}
	return nil
}

// ListSessions returns all sessions for an admin from Postgres.
func (sm *SessionManager) ListSessions(ctx context.Context, adminID string) ([]Session, error) {
	rows, err := sm.db.Query(ctx,
		`SELECT id, admin_id, ip_address, user_agent, created_at, expires_at
		 FROM sessions WHERE admin_id = $1 ORDER BY created_at DESC`, adminID)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	var sessions []Session
	for rows.Next() {
		var s Session
		var ip *net.IP
		if err := rows.Scan(&s.ID, &s.AdminID, &ip, &s.UserAgent, &s.CreatedAt, &s.ExpiresAt); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}
		if ip != nil {
			s.IPAddress = ip.String()
		}
		sessions = append(sessions, s)
	}
	return sessions, nil
}

// CleanExpired removes expired sessions from Postgres.
func (sm *SessionManager) CleanExpired(ctx context.Context) (int64, error) {
	result, err := sm.db.Exec(ctx, `DELETE FROM sessions WHERE expires_at < NOW()`)
	if err != nil {
		return 0, fmt.Errorf("clean expired sessions: %w", err)
	}
	return result.RowsAffected(), nil
}

func sha256Hash(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func valkeySessionKey(sessionID string) string {
	return "session:" + sessionID
}
