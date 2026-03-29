package api

import (
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/repository"
)

var validEmailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type createAdminRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

// adminView is the public representation of an admin (never includes password_hash).
type adminView struct {
	ID          string  `json:"id"`
	Email       string  `json:"email"`
	Role        string  `json:"role"`
	TOTPEnabled bool    `json:"totp_enabled"`
	CreatedAt   string  `json:"created_at"`
	LastLoginAt *string `json:"last_login_at,omitempty"`
}

func toAdminView(a repository.Admin) adminView {
	v := adminView{
		ID:          a.ID,
		Email:       a.Email,
		Role:        a.Role,
		TOTPEnabled: a.TOTPEnabled,
		CreatedAt:   a.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
	if a.LastLoginAt != nil {
		s := a.LastLoginAt.Format("2006-01-02T15:04:05Z")
		v.LastLoginAt = &s
	}
	return v
}

// --- GET /api/v1/admins ---

func (s *Server) handleListAdmins(w http.ResponseWriter, r *http.Request) {
	admins, err := s.admins.List(r.Context())
	if err != nil {
		s.logger.Error("list admins failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list admins")
		return
	}

	views := make([]adminView, 0, len(admins))
	for _, a := range admins {
		views = append(views, toAdminView(a))
	}

	respond(w, r, http.StatusOK, views)
}

// --- POST /api/v1/admins ---

func (s *Server) handleCreateAdmin(w http.ResponseWriter, r *http.Request) {
	var req createAdminRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if req.Email == "" || req.Password == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "Email and password are required")
		return
	}
	if !validEmailRe.MatchString(req.Email) {
		respondError(w, r, http.StatusBadRequest, "INVALID_EMAIL", "Invalid email address format")
		return
	}
	if err := auth.ValidatePasswordStrength(req.Password); err != nil {
		respondError(w, r, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
		return
	}

	role := req.Role
	if role == "" {
		role = "admin"
	}
	if role != "admin" && role != "superadmin" {
		respondError(w, r, http.StatusBadRequest, "INVALID_ROLE", "Role must be 'admin' or 'superadmin'")
		return
	}

	// Check uniqueness.
	existing, _ := s.admins.GetByEmail(r.Context(), req.Email)
	if existing != nil {
		respondError(w, r, http.StatusConflict, "ADMIN_EXISTS", "An admin with this email already exists")
		return
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		s.logger.Error("hash password failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to hash password")
		return
	}

	admin, err := s.admins.Create(r.Context(), repository.AdminCreate{
		Email:        req.Email,
		PasswordHash: hash,
		Role:         role,
	})
	if err != nil {
		s.logger.Error("create admin failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create admin")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "admin.create", "admin", &admin.ID,
		map[string]string{"email": admin.Email, "role": admin.Role}, &ip)

	respond(w, r, http.StatusCreated, toAdminView(*admin))
}

// --- DELETE /api/v1/admins/{adminID} ---

func (s *Server) handleDeleteAdmin(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "adminID")

	// Require confirmation header.
	if r.Header.Get("X-Confirm-Delete") != "true" {
		respondError(w, r, http.StatusBadRequest, "CONFIRMATION_REQUIRED",
			"Set X-Confirm-Delete: true header to confirm deletion")
		return
	}

	// Cannot delete yourself.
	currentAdminID := getAdminID(r.Context())
	if currentAdminID == targetID {
		respondError(w, r, http.StatusBadRequest, "CANNOT_DELETE_SELF",
			"You cannot delete your own admin account")
		return
	}

	deleted, err := s.admins.Delete(r.Context(), targetID)
	if err != nil {
		s.logger.Error("delete admin failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete admin")
		return
	}
	if !deleted {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Admin not found")
		return
	}

	ip := clientIP(r)
	s.audit.Log(r.Context(), &currentAdminID, "admin.delete", "admin", &targetID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Admin deleted"})
}
