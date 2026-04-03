package api

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/mail"
	vectismetrics "github.com/Veltara-Works/vectis/internal/metrics"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// inboundNotification is the payload POSTed by the Postfix notification script
// after a message is delivered to Dovecot.
type inboundNotification struct {
	MessageID    string  `json:"message_id"`
	From         string  `json:"from"`
	To           string  `json:"to"`       // envelope recipient
	Domain       string  `json:"domain"`   // recipient domain
	Subject      string  `json:"subject"`
	Size         int     `json:"size"`     // message size in bytes
	SpamScore    float64 `json:"spam_score,omitempty"`
	SpamAction   string  `json:"spam_action,omitempty"` // "no action", "add header", "reject", "greylist"
	QueueID      string  `json:"queue_id,omitempty"`
	EnvelopeFrom string  `json:"envelope_from,omitempty"` // SMTP MAIL FROM
	EnvelopeTo   string  `json:"envelope_to,omitempty"`   // SMTP RCPT TO
	RawMessageB64 string `json:"raw_message_b64,omitempty"` // base64-encoded full RFC 5322 message
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

	// Store inbound message metadata.
	if s.messages != nil {
		status := "delivered"
		if notif.SpamAction != "" && notif.SpamAction != "no action" {
			status = "spam"
		}
		var spamScore *float64
		if notif.SpamScore > 0 {
			spamScore = &notif.SpamScore
		}
		var spamAction *string
		if notif.SpamAction != "" {
			spamAction = &notif.SpamAction
		}
		var queueID *string
		if notif.QueueID != "" {
			queueID = &notif.QueueID
		}
		s.messages.Create(r.Context(), &repository.Message{
			DomainID:   domain.ID,
			MessageID:  notif.MessageID,
			Direction:  "inbound",
			Sender:     notif.From,
			Recipients: []string{notif.To},
			Subject:    notif.Subject,
			SizeBytes:  notif.Size,
			Status:     status,
			SpamScore:  spamScore,
			SpamAction: spamAction,
			QueueID:    queueID,
			CreatedAt:  time.Now().UTC(),
		})
	}

	// Increment domain stats.
	if s.mailStats != nil {
		s.mailStats.Increment(r.Context(), domain.ID, "received", notif.Size)
		if notif.SpamAction != "" && notif.SpamAction != "no action" {
			s.mailStats.Increment(r.Context(), domain.ID, "spam", 0)
		}
	}

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

	// Fire mail.received.full webhook if raw message is present.
	// This provides the full parsed email body, attachments, and envelope
	// for inbound routing integrations (e.g. ValidonX support ticket creation).
	if notif.RawMessageB64 != "" && s.webhookDispatcher != nil {
		go s.dispatchFullInbound(domain.ID, notif)
	}

	respond(w, r, http.StatusOK, map[string]string{"status": "processed"})
}

// dispatchFullInbound parses the raw RFC 5322 message and fires a
// mail.received.full webhook with body content, attachments, and envelope.
func (s *Server) dispatchFullInbound(domainID string, notif inboundNotification) {
	rawBytes, err := base64.StdEncoding.DecodeString(notif.RawMessageB64)
	if err != nil {
		s.logger.Error("decode raw inbound message failed", "error", err, "message_id", notif.MessageID)
		return
	}

	parsed, err := mail.ParseRawMessage(rawBytes)
	if err != nil {
		s.logger.Error("parse inbound message failed", "error", err, "message_id", notif.MessageID)
		return
	}

	// Build the To list from parsed headers (may differ from envelope).
	toList := make([]map[string]string, len(parsed.To))
	for i, a := range parsed.To {
		toList[i] = map[string]string{"name": a.Name, "email": a.Email}
	}

	ccList := make([]map[string]string, len(parsed.CC))
	for i, a := range parsed.CC {
		ccList[i] = map[string]string{"name": a.Name, "email": a.Email}
	}

	// Build attachment metadata.
	attachments := make([]map[string]any, len(parsed.Attachments))
	for i, a := range parsed.Attachments {
		attachments[i] = map[string]any{
			"filename":       a.Filename,
			"content_type":   a.ContentType,
			"size":           a.Size,
			"content_base64": a.ContentBase64,
		}
	}

	// Envelope — SMTP-level sender/recipient.
	envelopeFrom := notif.EnvelopeFrom
	if envelopeFrom == "" {
		envelopeFrom = parsed.From.Email
	}
	envelopeTo := []string{notif.EnvelopeTo}
	if notif.EnvelopeTo == "" && notif.To != "" {
		envelopeTo = []string{notif.To}
	}

	data := map[string]any{
		"message_id": parsed.MessageID,
		"from":       map[string]string{"name": parsed.From.Name, "email": parsed.From.Email},
		"to":         toList,
		"cc":         ccList,
		"subject":    parsed.Subject,
		"body_text":  parsed.BodyText,
		"body_html":  parsed.BodyHTML,
		"attachments": attachments,
		"headers":    parsed.Headers,
		"envelope": map[string]any{
			"mail_from": envelopeFrom,
			"rcpt_to":   envelopeTo,
		},
		"domain":      notif.Domain,
		"size":        notif.Size,
		"spam_score":  notif.SpamScore,
		"spam_action": notif.SpamAction,
		"queue_id":    notif.QueueID,
	}

	if parsed.ReplyTo != nil {
		data["reply_to"] = map[string]string{"name": parsed.ReplyTo.Name, "email": parsed.ReplyTo.Email}
	}

	ctx := context.Background()
	s.webhookDispatcher.Dispatch(ctx, domainID, mail.WebhookEvent{
		ID:        parsed.MessageID,
		Event:     "mail.received.full",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      data,
	})
}
