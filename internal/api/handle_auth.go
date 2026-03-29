package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/auth"
)

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginResponse struct {
	Admin     adminProfile `json:"admin"`
	SessionID string       `json:"session_id"`
	ExpiresAt time.Time    `json:"expires_at"`
}

type adminProfile struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	TOTPEnabled bool       `json:"totp_enabled"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "Email and password are required")
		return
	}

	// Look up admin.
	admin, err := s.admins.GetByEmail(r.Context(), req.Email)
	if err != nil {
		s.logger.Error("login lookup failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Internal server error")
		return
	}
	if admin == nil {
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password")
		return
	}

	// Verify password.
	ok, err := auth.VerifyPassword(req.Password, admin.PasswordHash)
	if err != nil || !ok {
		// Log the attempt for audit.
		adminID := admin.ID
		ip := clientIP(r)
		s.audit.Log(r.Context(), &adminID, "auth.login", "admin", &adminID,
			map[string]any{"success": false, "ip": ip}, &ip)
		respondError(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "Invalid email or password")
		return
	}

	// Create session.
	token, session, err := s.sessions.CreateSession(r.Context(), admin.ID, clientIP(r), r.UserAgent())
	if err != nil {
		s.logger.Error("create session failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create session")
		return
	}

	// Update last login.
	s.admins.UpdateLastLogin(r.Context(), admin.ID)

	// Set HMAC-signed session cookie. The cookie value is "token.signature"
	// per ADR-020 (signed cookies) and Spec B.6 (token as cookie value).
	signedToken := s.sessions.SignToken(token)
	http.SetCookie(w, &http.Cookie{
		Name:     "vectis_session",
		Value:    signedToken,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		Expires:  session.ExpiresAt,
	})

	// Audit log.
	ip := clientIP(r)
	s.audit.Log(r.Context(), &admin.ID, "auth.login", "admin", &admin.ID,
		map[string]any{"success": true, "ip": ip}, &ip)

	respond(w, r, http.StatusOK, loginResponse{
		Admin: adminProfile{
			ID:          admin.ID,
			Email:       admin.Email,
			Role:        admin.Role,
			TOTPEnabled: admin.TOTPEnabled,
			LastLoginAt: admin.LastLoginAt,
		},
		SessionID: session.ID,
		ExpiresAt: session.ExpiresAt,
	})
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	sessionID := getSessionID(r.Context())
	if err := s.sessions.DeleteSession(r.Context(), sessionID); err != nil {
		s.logger.Error("logout failed", "error", err)
	}

	// Clear cookie.
	http.SetCookie(w, &http.Cookie{
		Name:     "vectis_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	respond(w, r, http.StatusOK, map[string]string{"message": "Logged out"})
}

func (s *Server) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	adminID := getAdminID(r.Context())
	if err := s.sessions.DeleteAllSessions(r.Context(), adminID); err != nil {
		s.logger.Error("logout-all failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to invalidate sessions")
		return
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "vectis_session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})

	respond(w, r, http.StatusOK, map[string]string{"message": "All sessions invalidated"})
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	adminID := getAdminID(r.Context())
	sessions, err := s.sessions.ListSessions(r.Context(), adminID)
	if err != nil {
		s.logger.Error("list sessions failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list sessions")
		return
	}
	respond(w, r, http.StatusOK, sessions)
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	sessionID := chi.URLParam(r, "sessionID")
	if err := s.sessions.DeleteSession(r.Context(), sessionID); err != nil {
		s.logger.Error("delete session failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete session")
		return
	}
	respond(w, r, http.StatusOK, map[string]string{"message": "Session invalidated"})
}
