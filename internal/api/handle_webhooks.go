package api

import (
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/repository"
)

var validWebhookEvents = map[string]bool{
	"mail.sent":           true,
	"mail.delivered":      true,
	"mail.bounced":        true,
	"mail.failed":         true,
	"mail.complained":     true,
	"mail.received":       true,
	"mail.received.full":  true,
	"mail.spam":           true,
	"*":                   true,
}

type createWebhookRequest struct {
	DomainID *string  `json:"domain_id,omitempty"` // null = global
	URL      string   `json:"url"`
	Events   []string `json:"events"` // e.g. ["mail.sent", "mail.bounced"]
}

type webhookView struct {
	ID        string   `json:"id"`
	DomainID  *string  `json:"domain_id,omitempty"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Active    bool     `json:"active"`
	CreatedBy string   `json:"created_by"`
	CreatedAt string   `json:"created_at"`
}

func toWebhookView(w repository.Webhook) webhookView {
	return webhookView{
		ID:        w.ID,
		DomainID:  w.DomainID,
		URL:       w.URL,
		Events:    w.Events,
		Active:    w.Active,
		CreatedBy: w.CreatedBy,
		CreatedAt: w.CreatedAt.Format("2006-01-02T15:04:05Z"),
	}
}

// --- GET /api/v1/webhooks ---

func (s *Server) handleListWebhooks(w http.ResponseWriter, r *http.Request) {
	webhooks, err := s.webhooks.ListAll(r.Context())
	if err != nil {
		s.logger.Error("list webhooks failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to list webhooks")
		return
	}

	views := make([]webhookView, 0, len(webhooks))
	for _, wh := range webhooks {
		views = append(views, toWebhookView(wh))
	}
	respond(w, r, http.StatusOK, views)
}

// --- POST /api/v1/webhooks ---

func (s *Server) handleCreateWebhook(w http.ResponseWriter, r *http.Request) {
	var req createWebhookRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if req.URL == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "url is required")
		return
	}
	if !strings.HasPrefix(req.URL, "https://") {
		respondError(w, r, http.StatusBadRequest, "INVALID_URL", "Webhook URL must use HTTPS")
		return
	}
	if len(req.Events) == 0 {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "at least one event type is required")
		return
	}
	for _, e := range req.Events {
		if !validWebhookEvents[e] {
			respondError(w, r, http.StatusBadRequest, "INVALID_EVENT",
				"Unknown event type: "+e)
			return
		}
	}

	// Domain access check if scoped.
	if req.DomainID != nil && *req.DomainID != "" {
		if !s.canAccessDomain(r.Context(), *req.DomainID) {
			respondError(w, r, http.StatusForbidden, "FORBIDDEN", "You do not have access to this domain")
			return
		}
	}

	// Generate signing secret.
	secretBytes := make([]byte, 32)
	rand.Read(secretBytes)
	secret := hex.EncodeToString(secretBytes)

	wh, err := s.webhooks.Create(r.Context(), repository.WebhookCreate{
		DomainID:  req.DomainID,
		URL:       req.URL,
		Secret:    secret,
		Events:    req.Events,
		CreatedBy: getAdminID(r.Context()),
	})
	if err != nil {
		s.logger.Error("create webhook failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to create webhook")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "webhook.create", "webhook", &wh.ID,
		map[string]string{"url": wh.URL}, &ip)

	// Return view + secret (secret shown only at creation, like API keys).
	type createResponse struct {
		webhookView
		Secret string `json:"secret"`
	}
	respond(w, r, http.StatusCreated, createResponse{
		webhookView: toWebhookView(*wh),
		Secret:      secret,
	})
}

// --- DELETE /api/v1/webhooks/{webhookID} ---

func (s *Server) handleDeleteWebhook(w http.ResponseWriter, r *http.Request) {
	webhookID := chi.URLParam(r, "webhookID")

	deleted, err := s.webhooks.Delete(r.Context(), webhookID)
	if err != nil {
		s.logger.Error("delete webhook failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to delete webhook")
		return
	}
	if !deleted {
		respondError(w, r, http.StatusNotFound, "NOT_FOUND", "Webhook not found")
		return
	}

	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "webhook.delete", "webhook", &webhookID, nil, &ip)

	respond(w, r, http.StatusOK, map[string]string{"message": "Webhook deleted"})
}
