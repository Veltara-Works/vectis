package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"time"

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
// Valkey is the authority for session validity.
// Postgres is the authority for session inventory.
type SessionManager struct {
	db    *pgxpool.Pool
	vk    valkey.Client
	ttl   time.Duration
}

// NewSessionManager creates a session manager.
func NewSessionManager(db *pgxpool.Pool, vk valkey.Client, ttlHours int) *SessionManager {
	return &SessionManager{
		db:  db,
		vk:  vk,
		ttl: time.Duration(ttlHours) * time.Hour,
	}
}

// CreateSession generates a new session for an admin, stores it in both
// Valkey and Postgres, and returns the raw token (to be set as cookie).
func (sm *SessionManager) CreateSession(ctx context.Context, adminID, ipAddress, userAgent string) (token string, session *Session, err error) {
	// Generate 256-bit random token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}
	token = hex.EncodeToString(tokenBytes)

	// SHA-256 hash for Postgres storage (never store raw token in DB).
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

	// Store in Valkey (authority for validity). Value = admin_id.
	vkCmd := sm.vk.B().Set().Key(valkeySessionKey(sessionID)).Value(adminID).Ex(sm.ttl).Build()
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

// ValidateSession checks if a session is valid by looking up the session ID in Valkey.
// Returns the admin_id if valid.
func (sm *SessionManager) ValidateSession(ctx context.Context, sessionID string) (adminID string, err error) {
	cmd := sm.vk.B().Get().Key(valkeySessionKey(sessionID)).Build()
	result, err := sm.vk.Do(ctx, cmd).ToString()
	if err != nil {
		if valkey.IsValkeyNil(err) {
			return "", fmt.Errorf("session expired or invalid")
		}
		return "", fmt.Errorf("validate session: %w", err)
	}
	return result, nil
}

// DeleteSession removes a session from both Valkey and Postgres.
func (sm *SessionManager) DeleteSession(ctx context.Context, sessionID string) error {
	// Remove from Valkey.
	cmd := sm.vk.B().Del().Key(valkeySessionKey(sessionID)).Build()
	sm.vk.Do(ctx, cmd)

	// Remove from Postgres.
	_, err := sm.db.Exec(ctx, `DELETE FROM sessions WHERE id = $1`, sessionID)
	if err != nil {
		return fmt.Errorf("delete session from postgres: %w", err)
	}
	return nil
}

// DeleteAllSessions removes all sessions for an admin.
func (sm *SessionManager) DeleteAllSessions(ctx context.Context, adminID string) error {
	// Get all session IDs from Postgres.
	rows, err := sm.db.Query(ctx, `SELECT id FROM sessions WHERE admin_id = $1`, adminID)
	if err != nil {
		return fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	var sessionIDs []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return fmt.Errorf("scan session id: %w", err)
		}
		sessionIDs = append(sessionIDs, id)
	}

	// Delete from Valkey.
	for _, id := range sessionIDs {
		cmd := sm.vk.B().Del().Key(valkeySessionKey(id)).Build()
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
