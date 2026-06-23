package api

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// SCIM provisioning token management (super_admin + Enterprise-gated). These
// endpoints live under /api/v1 and back the License/SSO admin page: a
// super_admin mints a Bearer token here, pastes it (plus the SCIM base URL)
// into their IdP (Okta/Azure), and the IdP uses it against /scim/v2. The raw
// token is shown exactly once at creation; only its SHA-256 hash is persisted.
//
// Phase 1 is single-active-token-per-install: creating a new token revokes any
// existing active ones (this is the "regenerate/rotate" action). DELETE revokes
// a specific token without minting a replacement.

type createSCIMTokenRequest struct {
	ExpiresInDays *int `json:"expires_in_days,omitempty"` // 0 or omit = never
}

type createSCIMTokenResponse struct {
	Token       string               `json:"token"`        // raw token — shown only once
	SCIMToken   repository.SCIMToken `json:"scim_token"`   // persisted row (no hash)
	EndpointURL string               `json:"endpoint_url"` // SCIM base URL to paste into the IdP
}

// --- GET /api/v1/scim-tokens ---

func (s *Server) handleListSCIMTokens(w http.ResponseWriter, r *http.Request) {
	tokens, err := s.scimTokens.ListAll(r.Context())
	if err != nil {
		s.logger.Error("list scim tokens failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list SCIM tokens")
		return
	}
	if tokens == nil {
		tokens = []repository.SCIMToken{}
	}
	respond(w, r, http.StatusOK, tokens)
}

// --- POST /api/v1/scim-tokens ---

func (s *Server) handleCreateSCIMToken(w http.ResponseWriter, r *http.Request) {
	var req createSCIMTokenRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	var expiresAt *time.Time
	if req.ExpiresInDays != nil && *req.ExpiresInDays > 0 {
		t := time.Now().UTC().AddDate(0, 0, *req.ExpiresInDays)
		expiresAt = &t
	}

	// Single-active-token (Phase 1): minting a new token rotates out any
	// existing active ones so a leaked/old token can't keep provisioning.
	existing, err := s.scimTokens.ListAll(r.Context())
	if err != nil {
		s.logger.Error("list scim tokens before rotate failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create SCIM token")
		return
	}
	for _, t := range existing {
		if !t.Active {
			continue
		}
		if _, err := s.scimTokens.Revoke(r.Context(), t.ID); err != nil {
			s.logger.Error("revoke prior scim token failed", "error", err, "token_id", t.ID)
			respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create SCIM token")
			return
		}
	}

	rawToken, tokenHash, tokenPrefix, err := auth.GenerateSCIMToken()
	if err != nil {
		s.logger.Error("generate scim token failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to generate SCIM token")
		return
	}

	token, err := s.scimTokens.Create(r.Context(), repository.SCIMTokenCreate{
		TokenHash:   tokenHash,
		TokenPrefix: tokenPrefix,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		s.logger.Error("create scim token failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create SCIM token")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "scim_token.create", "scim_token", &token.ID,
		map[string]string{"prefix": token.TokenPrefix}, &ip)

	respond(w, r, http.StatusCreated, createSCIMTokenResponse{
		Token:       rawToken,
		SCIMToken:   *token,
		EndpointURL: s.scimBaseURL(r) + "/scim/v2",
	})
}

// --- DELETE /api/v1/scim-tokens/{tokenID} ---

func (s *Server) handleRevokeSCIMToken(w http.ResponseWriter, r *http.Request) {
	tokenID := chi.URLParam(r, "tokenID")

	revoked, err := s.scimTokens.Revoke(r.Context(), tokenID)
	if err != nil {
		s.logger.Error("revoke scim token failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to revoke SCIM token")
		return
	}
	if !revoked {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "SCIM token not found")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "scim_token.revoke", "scim_token", &tokenID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "SCIM token revoked"})
}
