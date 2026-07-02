package api

import (
	"context"
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/repository"
)

var validEmailRe = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)

type createAdminRequest struct {
	Email     string   `json:"email"`
	Password  string   `json:"password"`
	Role      string   `json:"role"`
	DomainIDs []string `json:"domain_ids,omitempty"` // required when role is domain_admin
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
	role := getAdminRole(r.Context())

	// domain_admin can only see their own record.
	if role == auth.RoleDomainAdmin {
		admin, err := s.admins.GetByID(r.Context(), getAdminID(r.Context()))
		if err != nil || admin == nil {
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get admin")
			return
		}
		respond(w, r, http.StatusOK, []adminView{toAdminView(*admin)})
		return
	}

	admins, err := s.admins.List(r.Context())
	if err != nil {
		s.logger.Error("list admins failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list admins")
		return
	}

	views := make([]adminView, 0, len(admins))
	for _, a := range admins {
		// Non-super_admin callers must not see the super_admin roster
		// (emails + last_login_at). Admin mutations are already
		// super_admin-only, so exposing the full list to a plain admin
		// leaked exactly what the mutation side hides (audit D-L4/K6).
		if role != auth.RoleSuperAdmin && a.Role == auth.RoleSuperAdmin {
			continue
		}
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
		role = auth.RoleAdmin
	}
	if !auth.IsValidRole(role) {
		respondError(w, r, http.StatusBadRequest, "INVALID_ROLE",
			"Role must be 'super_admin', 'admin', or 'domain_admin'")
		return
	}
	if role == auth.RoleDomainAdmin && len(req.DomainIDs) == 0 {
		respondError(w, r, http.StatusBadRequest, "MISSING_DOMAINS",
			"domain_ids is required when role is domain_admin")
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

	// Assign domains for domain_admin role.
	if role == auth.RoleDomainAdmin && len(req.DomainIDs) > 0 {
		if err := s.adminDomains.ReplaceAll(r.Context(), admin.ID, req.DomainIDs); err != nil {
			s.logger.Error("assign admin domains failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to assign domains")
			return
		}
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "admin.create", "admin", &admin.ID,
		map[string]string{"email": admin.Email, "role": admin.Role}, &ip)

	respond(w, r, http.StatusCreated, toAdminView(*admin))
}

// updateAdminRequest holds optional fields for PATCH /admins/{id}. All fields
// are pointers so the handler can distinguish "not provided" from "empty".
// TOTPCode is required if the acting admin has TOTP enabled (mirrors the
// DELETE /auth/totp pattern for sensitive self-serve actions).
type updateAdminRequest struct {
	Email     *string  `json:"email,omitempty"`
	Password  *string  `json:"password,omitempty"`
	Role      *string  `json:"role,omitempty"`
	DomainIDs []string `json:"domain_ids,omitempty"`
	TOTPCode  string   `json:"totp_code,omitempty"`
}

// countSuperAdmins returns the number of admins with role super_admin.
func (s *Server) countSuperAdmins(ctx context.Context) (int, error) {
	admins, err := s.admins.List(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, a := range admins {
		if a.Role == auth.RoleSuperAdmin {
			n++
		}
	}
	return n, nil
}

// requireTOTPIfEnabled checks that the acting admin supplied a valid TOTP code
// if they have TOTP enabled. Returns true if the request should proceed.
func (s *Server) requireTOTPIfEnabled(w http.ResponseWriter, r *http.Request, code string) bool {
	acting, err := s.admins.GetByID(r.Context(), getAdminID(r.Context()))
	if err != nil || acting == nil {
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load acting admin")
		return false
	}
	if !acting.TOTPEnabled || acting.TOTPSecret == nil {
		return true
	}
	if code == "" {
		respondError(w, r, http.StatusBadRequest, "TOTP_REQUIRED",
			"TOTP code required for this action (include totp_code in the request body)")
		return false
	}
	valid, err := s.totpManager.ValidateCodeWithSkew(*acting.TOTPSecret, code)
	if err != nil || !valid {
		respondError(w, r, http.StatusUnauthorized, "TOTP_INVALID", "Invalid TOTP code")
		return false
	}
	return true
}

// --- PATCH /api/v1/admins/{adminID} ---

func (s *Server) handleUpdateAdmin(w http.ResponseWriter, r *http.Request) {
	targetID := chi.URLParam(r, "adminID")

	var req updateAdminRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if req.Email == nil && req.Password == nil && req.Role == nil && req.DomainIDs == nil {
		respondError(w, r, http.StatusBadRequest, "NO_FIELDS",
			"Provide at least one of: email, password, role, domain_ids")
		return
	}

	target, err := s.admins.GetByID(r.Context(), targetID)
	if err != nil {
		s.logger.Error("get admin failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load admin")
		return
	}
	if target == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Admin not found")
		return
	}

	// TOTP gate for the acting admin.
	if !s.requireTOTPIfEnabled(w, r, req.TOTPCode) {
		return
	}

	update := repository.AdminUpdate{}

	if req.Email != nil {
		if !validEmailRe.MatchString(*req.Email) {
			respondError(w, r, http.StatusBadRequest, "INVALID_EMAIL", "Invalid email address format")
			return
		}
		if *req.Email != target.Email {
			existing, _ := s.admins.GetByEmail(r.Context(), *req.Email)
			if existing != nil {
				respondError(w, r, http.StatusConflict, "ADMIN_EXISTS", "An admin with this email already exists")
				return
			}
		}
		update.Email = req.Email
	}

	if req.Password != nil {
		if err := auth.ValidatePasswordStrength(*req.Password); err != nil {
			respondError(w, r, http.StatusBadRequest, "WEAK_PASSWORD", err.Error())
			return
		}
		hash, err := auth.HashPassword(*req.Password)
		if err != nil {
			s.logger.Error("hash password failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to hash password")
			return
		}
		update.PasswordHash = &hash
	}

	if req.Role != nil {
		if !auth.IsValidRole(*req.Role) {
			respondError(w, r, http.StatusBadRequest, "INVALID_ROLE",
				"Role must be 'super_admin', 'admin', or 'domain_admin'")
			return
		}
		// Last-super_admin demote guard.
		if target.Role == auth.RoleSuperAdmin && *req.Role != auth.RoleSuperAdmin {
			n, err := s.countSuperAdmins(r.Context())
			if err != nil {
				s.logger.Error("count super admins failed", "error", err)
				respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check super admin count")
				return
			}
			if n <= 1 {
				respondError(w, r, http.StatusBadRequest, "LAST_SUPER_ADMIN",
					"Cannot demote the last super_admin — promote another admin first")
				return
			}
		}
		// domain_admin must have at least one domain assigned.
		if *req.Role == auth.RoleDomainAdmin && target.Role != auth.RoleDomainAdmin && len(req.DomainIDs) == 0 {
			respondError(w, r, http.StatusBadRequest, "MISSING_DOMAINS",
				"domain_ids is required when promoting to domain_admin")
			return
		}
		update.Role = req.Role
	}

	updated, err := s.admins.Update(r.Context(), targetID, update)
	if err != nil {
		s.logger.Error("update admin failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update admin")
		return
	}
	if updated == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Admin not found")
		return
	}

	// Replace domain assignments if domain_ids provided (only meaningful for domain_admin).
	effectiveRole := updated.Role
	if req.DomainIDs != nil && effectiveRole == auth.RoleDomainAdmin {
		if err := s.adminDomains.ReplaceAll(r.Context(), targetID, req.DomainIDs); err != nil {
			s.logger.Error("replace admin domains failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to update domain assignments")
			return
		}
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	changed := map[string]bool{}
	if req.Email != nil {
		changed["email"] = true
	}
	if req.Password != nil {
		changed["password"] = true
	}
	if req.Role != nil {
		changed["role"] = true
	}
	if req.DomainIDs != nil {
		changed["domain_ids"] = true
	}
	s.audit.Log(r.Context(), &adminID, "admin.update", "admin", &targetID, changed, &ip)

	respond(w, r, http.StatusOK, toAdminView(*updated))
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

	// Last-super_admin guard.
	target, err := s.admins.GetByID(r.Context(), targetID)
	if err != nil {
		s.logger.Error("get admin failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to load admin")
		return
	}
	if target == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Admin not found")
		return
	}
	if target.Role == auth.RoleSuperAdmin {
		n, err := s.countSuperAdmins(r.Context())
		if err != nil {
			s.logger.Error("count super admins failed", "error", err)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to check super admin count")
			return
		}
		if n <= 1 {
			respondError(w, r, http.StatusBadRequest, "LAST_SUPER_ADMIN",
				"Cannot delete the last super_admin — promote another admin first")
			return
		}
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
