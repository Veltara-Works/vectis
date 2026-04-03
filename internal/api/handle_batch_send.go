package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/mail"
	vectismetrics "github.com/Veltara-Works/vectis/internal/metrics"
	"github.com/Veltara-Works/vectis/internal/repository"
)

const maxBatchSize = 100

type batchSendRequest struct {
	Messages []sendRequest `json:"messages"`
}

type batchSendResult struct {
	Index     int    `json:"index"`
	MessageID string `json:"message_id,omitempty"`
	Error     string `json:"error,omitempty"`
	Code      string `json:"code,omitempty"`
}

type batchSendResponse struct {
	Total     int               `json:"total"`
	Succeeded int               `json:"succeeded"`
	Failed    int               `json:"failed"`
	Results   []batchSendResult `json:"results"`
}

// handleBatchSend accepts an array of messages and sends each one, returning
// per-message results. Maximum 100 messages per batch.
func (s *Server) handleBatchSend(w http.ResponseWriter, r *http.Request) {
	var req batchSendRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	if len(req.Messages) == 0 {
		respondError(w, r, http.StatusBadRequest, "EMPTY_BATCH", "messages array is required and must not be empty")
		return
	}
	if len(req.Messages) > maxBatchSize {
		respondError(w, r, http.StatusBadRequest, "BATCH_TOO_LARGE",
			"Maximum batch size is 100 messages")
		return
	}

	if s.mailSender == nil {
		respondError(w, r, http.StatusServiceUnavailable, "SEND_UNAVAILABLE",
			"Sending is not configured on this server")
		return
	}

	adminID := getAdminID(r.Context())
	adminRole := getAdminRole(r.Context())
	apiKeyID := getAPIKeyID(r.Context())
	ip := clientIP(r)

	resp := batchSendResponse{
		Total:   len(req.Messages),
		Results: make([]batchSendResult, len(req.Messages)),
	}

	for i, msg := range req.Messages {
		result := s.processSingleSend(r, msg, adminID, adminRole, apiKeyID, ip)
		resp.Results[i] = batchSendResult{
			Index:     i,
			MessageID: result.messageID,
			Error:     result.err,
			Code:      result.code,
		}
		if result.err == "" {
			resp.Succeeded++
		} else {
			resp.Failed++
		}
	}

	respond(w, r, http.StatusOK, resp)
}

type singleSendResult struct {
	messageID string
	err       string
	code      string
}

func (s *Server) processSingleSend(r *http.Request, req sendRequest, adminID, adminRole, apiKeyID, ip string) singleSendResult {
	// Validate required fields.
	if req.From.Email == "" {
		return singleSendResult{code: "MISSING_FIELDS", err: "from.email is required"}
	}
	if len(req.To) == 0 {
		return singleSendResult{code: "MISSING_FIELDS", err: "at least one recipient in 'to' is required"}
	}
	for _, a := range req.To {
		if a.Email == "" {
			return singleSendResult{code: "MISSING_FIELDS", err: "to[].email is required"}
		}
	}
	if req.Subject == "" {
		return singleSendResult{code: "MISSING_FIELDS", err: "subject is required"}
	}
	if req.TextBody == "" && req.HTMLBody == "" {
		return singleSendResult{code: "MISSING_FIELDS", err: "text_body or html_body is required"}
	}

	// Validate sender domain.
	senderDomain := extractDomain(req.From.Email)
	if senderDomain == "" {
		return singleSendResult{code: "INVALID_SENDER", err: "Invalid sender email address"}
	}

	domain, err := s.domains.GetByName(r.Context(), senderDomain)
	if err != nil {
		return singleSendResult{code: "INTERNAL_ERROR", err: "Failed to verify sender domain"}
	}
	if domain == nil {
		return singleSendResult{code: "DOMAIN_NOT_FOUND", err: "Sender domain '" + senderDomain + "' is not managed by this server"}
	}
	if !domain.Active {
		return singleSendResult{code: "DOMAIN_INACTIVE", err: "Sender domain '" + senderDomain + "' is inactive"}
	}

	// RBAC check.
	if !auth.CanAccessAllDomains(adminRole) {
		ok, _ := s.adminDomains.HasAccess(r.Context(), adminID, domain.ID)
		if !ok {
			return singleSendResult{code: "FORBIDDEN", err: "You do not have access to send from domain '" + senderDomain + "'"}
		}
	}

	// API key domain scoping.
	if apiKeyID != "" {
		apiKey, err := s.apiKeys.GetByID(r.Context(), apiKeyID)
		if err == nil && apiKey != nil && len(apiKey.ScopedDomainIDs) > 0 {
			scoped := false
			for _, did := range apiKey.ScopedDomainIDs {
				if did == domain.ID {
					scoped = true
					break
				}
			}
			if !scoped {
				return singleSendResult{code: "API_KEY_DOMAIN_SCOPE", err: "This API key does not have access to domain '" + senderDomain + "'"}
			}
		}
	}

	// Abuse detection.
	senderLocalPart := extractLocalPart(req.From.Email)
	if senderLocalPart != "" {
		mailbox, _ := s.mailboxes.GetByEmail(r.Context(), domain.ID, senderLocalPart)
		if mailbox != nil {
			suspended, reason, _ := s.abuseEvents.IsMailboxSuspended(r.Context(), mailbox.ID)
			if suspended {
				return singleSendResult{code: "MAILBOX_SUSPENDED", err: "Sending suspended: " + reason}
			}
			if s.abuseDetector != nil {
				check, checkErr := s.abuseDetector.CheckAndRecord(r.Context(), mailbox.ID, domain.ID)
				if checkErr == nil && !check.Allowed {
					s.abuseEvents.SuspendMailbox(r.Context(), mailbox.ID, check.Reason)
					vectismetrics.EmailsSendSuspended.Inc()
					return singleSendResult{code: "RATE_LIMIT_EXCEEDED", err: check.Reason}
				}
			}
		}
	}

	// Validate headers.
	for k := range req.Headers {
		if !strings.HasPrefix(k, "X-") {
			return singleSendResult{code: "INVALID_HEADER", err: "Custom headers must start with 'X-': " + k}
		}
	}

	// Build and send.
	msg := &mail.Message{
		From:        req.From,
		To:          req.To,
		CC:          req.CC,
		BCC:         req.BCC,
		ReplyTo:     req.ReplyTo,
		Subject:     req.Subject,
		TextBody:    req.TextBody,
		HTMLBody:    req.HTMLBody,
		Attachments: req.Attachments,
		Headers:     req.Headers,
	}

	result, err := s.mailSender.Send(msg)
	if err != nil {
		return singleSendResult{code: "SEND_FAILED", err: "Failed to send: " + err.Error()}
	}

	vectismetrics.EmailsSent.Inc()
	vectismetrics.BatchMessagesSent.Inc()

	// Audit log.
	s.audit.Log(r.Context(), &adminID, "mail.batch_send", "domain", &domain.ID,
		map[string]any{
			"message_id": result.MessageID,
			"from":       req.From.Email,
			"to_count":   len(req.To),
			"subject":    req.Subject,
			"api_key":    apiKeyID != "",
		}, &ip)

	// Store message metadata.
	if s.messages != nil {
		toEmails := allRecipients(req.To, req.CC, req.BCC)
		s.messages.Create(r.Context(), &repository.Message{
			DomainID:   domain.ID,
			MessageID:  result.MessageID,
			Direction:  "outbound",
			Sender:     req.From.Email,
			Recipients: toEmails,
			Subject:    req.Subject,
			Status:     "sent",
			CreatedAt:  time.Now().UTC(),
		})
	}

	// Increment domain stats.
	if s.mailStats != nil {
		s.mailStats.Increment(r.Context(), domain.ID, "sent", 0)
	}

	// Webhook dispatch.
	if s.webhookDispatcher != nil {
		toEmails := make([]string, len(req.To))
		for j, a := range req.To {
			toEmails[j] = a.Email
		}
		s.webhookDispatcher.Dispatch(r.Context(), domain.ID, mail.WebhookEvent{
			ID:        result.MessageID,
			Event:     "mail.sent",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Data: map[string]any{
				"message_id": result.MessageID,
				"from":       req.From.Email,
				"to":         toEmails,
				"subject":    req.Subject,
				"domain":     senderDomain,
				"batch":      true,
			},
		})
	}

	return singleSendResult{messageID: result.MessageID}
}

func allRecipients(to, cc, bcc []mail.Address) []string {
	var emails []string
	for _, a := range to {
		emails = append(emails, a.Email)
	}
	for _, a := range cc {
		emails = append(emails, a.Email)
	}
	for _, a := range bcc {
		emails = append(emails, a.Email)
	}
	return emails
}
