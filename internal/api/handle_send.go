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

type sendRequest struct {
	From        mail.Address      `json:"from"`
	To          []mail.Address    `json:"to"`
	CC          []mail.Address    `json:"cc,omitempty"`
	BCC         []mail.Address    `json:"bcc,omitempty"`
	ReplyTo     *mail.Address     `json:"reply_to,omitempty"`
	Subject     string            `json:"subject"`
	TextBody    string            `json:"text_body,omitempty"`
	HTMLBody    string            `json:"html_body,omitempty"`
	Attachments []mail.Attachment `json:"attachments,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	TrackOpens  bool              `json:"track_opens,omitempty"`
	TrackClicks bool              `json:"track_clicks,omitempty"`
}

type sendResponse struct {
	MessageID string `json:"message_id"`
}

// handleSend accepts a JSON email payload, validates it, and submits to Postfix.
// Requires API key or session auth. Enforces domain ownership.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	var req sendRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	// Validate required fields.
	if req.From.Email == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "from.email is required")
		return
	}
	if len(req.To) == 0 {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "at least one recipient in 'to' is required")
		return
	}
	for i, a := range req.To {
		if a.Email == "" {
			respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS",
				"to["+strings.Repeat("", 0)+string(rune('0'+i))+"].email is required")
			return
		}
	}
	if req.Subject == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "subject is required")
		return
	}
	if req.TextBody == "" && req.HTMLBody == "" {
		respondError(w, r, http.StatusBadRequest, "MISSING_FIELDS", "text_body or html_body is required")
		return
	}

	// Validate sender domain — must be a domain managed by Vectis.
	senderDomain := extractDomain(req.From.Email)
	if senderDomain == "" {
		respondError(w, r, http.StatusBadRequest, "INVALID_SENDER", "Invalid sender email address")
		return
	}

	domain, err := s.domains.GetByName(r.Context(), senderDomain)
	if err != nil {
		s.logger.Error("domain lookup failed", "error", err)
		respondError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to verify sender domain")
		return
	}
	if domain == nil {
		respondError(w, r, http.StatusForbidden, "DOMAIN_NOT_FOUND",
			"Sender domain '"+senderDomain+"' is not managed by this server")
		return
	}
	if !domain.Active {
		respondError(w, r, http.StatusForbidden, "DOMAIN_INACTIVE",
			"Sender domain '"+senderDomain+"' is inactive")
		return
	}

	// Check domain access (RBAC + API key scoping).
	if !s.canAccessDomain(r.Context(), domain.ID) {
		respondError(w, r, http.StatusForbidden, "FORBIDDEN",
			"You do not have access to send from domain '"+senderDomain+"'")
		return
	}

	// If authenticated via API key, check domain scoping.
	if apiKeyID := getAPIKeyID(r.Context()); apiKeyID != "" {
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
				respondError(w, r, http.StatusForbidden, "API_KEY_DOMAIN_SCOPE",
					"This API key does not have access to domain '"+senderDomain+"'")
				return
			}
		}
	}

	// Abuse detection: check sender mailbox suspension and rate limits.
	senderLocalPart := extractLocalPart(req.From.Email)
	if senderLocalPart != "" {
		mailbox, _ := s.mailboxes.GetByEmail(r.Context(), domain.ID, senderLocalPart)
		if mailbox != nil {
			// Check if mailbox is suspended from sending.
			suspended, reason, _ := s.abuseEvents.IsMailboxSuspended(r.Context(), mailbox.ID)
			if suspended {
				respondError(w, r, http.StatusForbidden, "MAILBOX_SUSPENDED",
					"Sending suspended for this mailbox: "+reason)
				return
			}

			// Rate check + spike detection.
			if s.abuseDetector != nil {
				check, err := s.abuseDetector.CheckAndRecord(r.Context(), mailbox.ID, domain.ID)
				if err != nil {
					s.logger.Error("abuse check failed", "error", err)
					// Fail open — don't block sending on abuse check errors.
				} else if !check.Allowed {
					// Auto-suspend the mailbox.
					s.abuseEvents.SuspendMailbox(r.Context(), mailbox.ID, check.Reason)
					action := "suspend"
					s.abuseEvents.LogEvent(r.Context(), &domain.ID, &mailbox.ID, "auto_suspend", "critical",
						map[string]any{"reason": check.Reason, "hourly_count": check.MailboxCount}, &action)

					vectismetrics.EmailsSendSuspended.Inc()
					respondError(w, r, http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", check.Reason)
					return
				} else if check.SpikeDetected {
					// Log spike alert but allow the send.
					action := "alert"
					s.abuseEvents.LogEvent(r.Context(), &domain.ID, &mailbox.ID, "rate_spike", "warn",
						map[string]any{"mailbox_hourly": check.MailboxCount, "domain_hourly": check.DomainCount}, &action)
				}
			}
		}
	}

	// Validate custom headers — only X-* allowed.
	for k := range req.Headers {
		if !strings.HasPrefix(k, "X-") {
			respondError(w, r, http.StatusBadRequest, "INVALID_HEADER",
				"Custom headers must start with 'X-': "+k)
			return
		}
	}

	// Check mail sender is initialized.
	if s.mailSender == nil {
		respondError(w, r, http.StatusServiceUnavailable, "SEND_UNAVAILABLE",
			"Sending is not configured on this server")
		return
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
	s.applyEngagementTracking(msg, req.TrackOpens, req.TrackClicks)

	result, err := s.mailSender.Send(msg)
	if err != nil {
		s.logger.Error("send failed", "error", err, "from", req.From.Email)
		respondError(w, r, http.StatusInternalServerError, "SEND_FAILED",
			"Failed to send message: "+err.Error())
		return
	}

	vectismetrics.EmailsSent.Inc()

	// Store message metadata.
	if s.messages != nil {
		toEmails := make([]string, 0, len(req.To)+len(req.CC)+len(req.BCC))
		for _, a := range req.To {
			toEmails = append(toEmails, a.Email)
		}
		for _, a := range req.CC {
			toEmails = append(toEmails, a.Email)
		}
		for _, a := range req.BCC {
			toEmails = append(toEmails, a.Email)
		}
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

	// Audit log.
	adminID := getAdminID(r.Context())
	ip := clientIP(r)
	s.audit.Log(r.Context(), &adminID, "mail.send", "domain", &domain.ID,
		map[string]any{
			"message_id": result.MessageID,
			"from":       req.From.Email,
			"to_count":   len(req.To),
			"subject":    req.Subject,
			"api_key":    getAPIKeyID(r.Context()) != "",
		}, &ip)

	// Fire mail.sent webhook event.
	if s.webhookDispatcher != nil {
		toEmails := make([]string, len(req.To))
		for i, a := range req.To {
			toEmails[i] = a.Email
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
			},
		})
	}

	respond(w, r, http.StatusOK, sendResponse{MessageID: result.MessageID})
}

// extractDomain returns the domain part of an email address.
func extractDomain(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[1] == "" {
		return ""
	}
	return strings.ToLower(parts[1])
}

// extractLocalPart returns the local part of an email address.
func extractLocalPart(email string) string {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[0] == "" {
		return ""
	}
	return strings.ToLower(parts[0])
}

// canSendAsDomain checks if the authenticated user (via session or API key)
// has access to send from the given domain. Uses existing RBAC.
func (s *Server) canSendAsDomain(r *http.Request, domainID string) bool {
	role := getAdminRole(r.Context())
	if auth.CanAccessAllDomains(role) {
		return true
	}
	return s.canAccessDomain(r.Context(), domainID)
}
