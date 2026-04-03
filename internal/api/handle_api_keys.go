package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/repository"
)

type createAPIKeyRequest struct {
	Name            string   `json:"name"`
	ScopedDomainIDs []string `json:"scoped_domain_ids,omitempty"`
	RateLimit       *int     `json:"rate_limit,omitempty"`   // requests per minute; default 60
	ExpiresInDays   *int     `json:"expires_in_days,omitempty"` // 0 or omit = never
}

type createAPIKeyResponse struct {
	Key    string          `json:"key"` // raw key — shown only once
	APIKey repository.APIKey `json:"api_key"`
}

// --- GET /api/v1/api-keys ---

func (s *Server) handleListAPIKeys(w http.ResponseWriter, r *http.Request) {
	role := getAdminRole(r.Context())
	adminID := getAdminID(r.Context())

	var keys []repository.APIKey
	var err error

	if auth.CanManageAdmins(role) {
		keys, err = s.apiKeys.ListAll(r.Context())
	} else {
		keys, err = s.apiKeys.ListByAdmin(r.Context(), adminID)
	}

	if err != nil {
		s.logger.Error("list api keys failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list API keys")
		return
	}

	if keys == nil {
		keys = []repository.APIKey{}
	}
	respond(w, r, http.StatusOK, keys)
}

// --- POST /api/v1/api-keys ---

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req createAPIKeyRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if req.Name == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "API key name is required")
		return
	}

	rawKey, keyHash, keyPrefix, err := auth.GenerateAPIKey()
	if err != nil {
		s.logger.Error("generate api key failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate API key")
		return
	}

	rateLimit := 60
	if req.RateLimit != nil && *req.RateLimit >= 0 {
		rateLimit = *req.RateLimit
	}

	var expiresAt *time.Time
	if req.ExpiresInDays != nil && *req.ExpiresInDays > 0 {
		t := time.Now().UTC().AddDate(0, 0, *req.ExpiresInDays)
		expiresAt = &t
	}

	apiKey, err := s.apiKeys.Create(r.Context(), repository.APIKeyCreate{
		AdminID:         getAdminID(r.Context()),
		Name:            req.Name,
		KeyHash:         keyHash,
		KeyPrefix:       keyPrefix,
		ScopedDomainIDs: req.ScopedDomainIDs,
		RateLimit:       rateLimit,
		ExpiresAt:       expiresAt,
	})
	if err != nil {
		s.logger.Error("create api key failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create API key")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "apikey.create", "api_key", &apiKey.ID,
		map[string]string{"name": apiKey.Name, "prefix": apiKey.KeyPrefix}, &ip)

	respond(w, r, http.StatusCreated, createAPIKeyResponse{
		Key:    rawKey,
		APIKey: *apiKey,
	})
}

// --- DELETE /api/v1/api-keys/{keyID} ---

func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "keyID")
	adminID := getAdminID(r.Context())
	role := getAdminRole(r.Context())

	// Verify ownership or super_admin.
	key, err := s.apiKeys.GetByID(r.Context(), keyID)
	if err != nil {
		s.logger.Error("get api key failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to get API key")
		return
	}
	if key == nil {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "API key not found")
		return
	}
	if key.AdminID != adminID && !auth.CanManageAdmins(role) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You can only revoke your own API keys")
		return
	}

	revoked, err := s.apiKeys.Revoke(r.Context(), keyID)
	if err != nil {
		s.logger.Error("revoke api key failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke API key")
		return
	}
	if !revoked {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "API key not found")
		return
	}

	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "apikey.revoke", "api_key", &keyID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "API key revoked"})
}
