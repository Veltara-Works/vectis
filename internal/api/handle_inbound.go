package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/mail"
	vectismetrics "github.com/Veltara-Works/vectis/internal/metrics"
)

// inboundNotification is the payload POSTed by the Postfix notification script
// after a message is delivered to Dovecot.
type inboundNotification struct {
	MessageID  string  `json:"message_id"`
	From       string  `json:"from"`
	To         string  `json:"to"`       // envelope recipient
	Domain     string  `json:"domain"`   // recipient domain
	Subject    string  `json:"subject"`
	Size       int     `json:"size"`     // message size in bytes
	SpamScore  float64 `json:"spam_score,omitempty"`
	SpamAction string  `json:"spam_action,omitempty"` // "no action", "add header", "reject", "greylist"
	QueueID    string  `json:"queue_id,omitempty"`
}

// handleInboundNotify receives delivery notifications from the Postfix
// notification script. Authenticated via internal token (X-Internal-Token header),
// not session auth — this is a service-to-service call.
func (s *Server) handleInboundNotify(w http.ResponseWriter, r *http.Request) {
	// Authenticate via internal token.
	token := r.Header.Get("X-Internal-Token")
	if token == "" || token != s.internalToken {
		respondError(w, r, http.StatusUnauthorized, "AUTH_REQUIRED", "Invalid internal token")
		return
	}

	var notif inboundNotification
	if err := decodeJSON(r, &notif); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if notif.To == "" || notif.Domain == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "to and domain are required")
		return
	}

	// Look up the recipient domain.
	recipientDomain := strings.ToLower(notif.Domain)
	domain, err := s.domains.GetByName(r.Context(), recipientDomain)
	if err != nil || domain == nil {
		// Domain not managed by us — ignore silently.
		respond(w, r, http.StatusOK, map[string]string{"status": "ignored"})
		return
	}

	vectismetrics.EmailsReceived.Inc()

	// Fire mail.received webhook event.
	if s.webhookDispatcher != nil {
		s.webhookDispatcher.Dispatch(r.Context(), domain.ID, mail.WebhookEvent{
			ID:        notif.MessageID,
			Event:     "mail.received",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Data: map[string]any{
				"message_id": notif.MessageID,
				"from":       notif.From,
				"to":         notif.To,
				"domain":     recipientDomain,
				"subject":    notif.Subject,
				"size":       notif.Size,
				"queue_id":   notif.QueueID,
			},
		})

		// Fire mail.spam event if Rspamd flagged it.
		if notif.SpamScore > 0 && notif.SpamAction != "" && notif.SpamAction != "no action" {
			vectismetrics.EmailsSpam.Inc()
			s.webhookDispatcher.Dispatch(r.Context(), domain.ID, mail.WebhookEvent{
				ID:        notif.MessageID,
				Event:     "mail.spam",
				Timestamp: time.Now().UTC().Format(time.RFC3339),
				Data: map[string]any{
					"message_id":  notif.MessageID,
					"from":        notif.From,
					"to":          notif.To,
					"domain":      recipientDomain,
					"spam_score":  notif.SpamScore,
					"spam_action": notif.SpamAction,
				},
			})
		}
	}

	respond(w, r, http.StatusOK, map[string]string{"status": "processed"})
}
