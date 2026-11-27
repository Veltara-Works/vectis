package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/auth"
)

const resetTokenTTL = 1 * time.Hour

const invalidResetLinkMsg = "This reset link is invalid, expired or already used. Request a new one."

// handleRequestPasswordReset creates a reset token and emails the link.
// Always returns 200 even if the email doesn't exist (prevents enumeration).
func (s *Server) handleRequestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decodeJSON(r, &req); err != nil || req.Email == "" {
		respondError(w, r, http.StatusBadRequest, "INVALID_INPUT", "email is required")
		return
	}

	// Per-target rate limit (audit D-L2): bound reset emails to a single
	// address regardless of source IP, to stop distributed reset-email bombing.
	// We still return 200 either way so this reveals nothing about the account.
	okResp := map[string]string{"message": "If the email exists, a reset link has been sent."}
	if s.resetLimiter != nil && !s.resetLimiter.allow("email:"+strings.ToLower(strings.TrimSpace(req.Email)), time.Now()) {
		respond(w, r, http.StatusOK, okResp)
		return
	}

	// The lookup + token mint + SMTP send happen on a detached goroutine and we
	// always respond 200 immediately, so the response time can't distinguish a
	// real account (slow DB write + mail round-trip) from a non-existent one
	// (fast) — closing the timing-oracle enumeration (audit D-L1). The body
	// already reveals nothing.
	go s.processPasswordResetRequest(req.Email, clientIP(r))

	respond(w, r, http.StatusOK, okResp)
}

// processPasswordResetRequest performs the actual reset-token work off the
// request path with a detached, bounded context. It silently returns for
// unknown emails.
func (s *Server) processPasswordResetRequest(email, ip string) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	admin, err := s.admins.GetByEmail(ctx, email)
	if err != nil || admin == nil {
		return
	}

	// Generate a 32-byte random token.
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		s.logger.Error("generate reset token failed", "error", err)
		return
	}
	rawToken := hex.EncodeToString(tokenBytes)
	hash := sha256sum(rawToken)

	// Store hashed token.
	if _, err := s.resetTokens.Create(ctx, admin.ID, hash, resetTokenTTL); err != nil {
		s.logger.Error("store reset token failed", "error", err)
		return
	}

	// Send email (best-effort).
	if err := s.notifications.SendPasswordReset(admin.Email, rawToken); err != nil {
		s.logger.Error("send password reset email failed", "error", err, "admin_id", admin.ID)
	}

	// Audit log.
	s.audit.Log(ctx, &admin.ID, "auth.password_reset_request", "admin", &admin.ID, nil, &ip)
}

// handleResetPassword validates the token and sets the new password.
func (s *Server) handleResetPassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_INPUT", "Invalid request body")
		return
	}
	if req.Token == "" || req.NewPassword == "" {
		respondError(w, r, http.StatusBadRequest, "INVALID_INPUT", "token and new_password are required")
		return
	}
	// Same rules as creating or editing an admin. Checked before the token is
	// used, so a rejected password doesn't use up the link.
	if err := auth.ValidatePasswordStrength(req.NewPassword); err != nil {
		respondError(w, r, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
		return
	}

	// Cheap, non-consuming check first, so an unknown or expired token never
	// costs an Argon2id hash (64 MiB).
	tokenHash := sha256sum(req.Token)
	found, err := s.resetTokens.FindByHash(r.Context(), tokenHash)
	if err != nil {
		s.logger.Error("find reset token failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to validate token")
		return
	}
	if found == nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_TOKEN", invalidResetLinkMsg)
		return
	}

	passwordHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		s.logger.Error("hash password failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to process password")
		return
	}

	// Use the token and save the password in one transaction: the link is
	// consumed only if the password is saved, and works exactly once even if
	// submitted twice at the same moment.
	token, err := s.resetTokens.Redeem(r.Context(), tokenHash, passwordHash)
	if err != nil {
		s.logger.Error("redeem reset token failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update password")
		return
	}
	if token == nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_TOKEN", invalidResetLinkMsg)
		return
	}

	// Invalidate all existing sessions (force re-login).
	s.sessions.DeleteAllSessions(r.Context(), token.AdminID)

	// Audit log.
	ip := clientIP(r)
	s.audit.Log(r.Context(), &token.AdminID, "auth.password_reset", "admin", &token.AdminID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Password has been reset. Please log in with your new password."})
}

func sha256sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}
