package api

import (
	"errors"
	"fmt"
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

// sendVariant captures the only legitimate differences between the single-send
// and batch-send paths: the audit action recorded and the batch-only metric /
// webhook flag. Everything else — validation, sender-domain authorization, abuse
// control, the SMTP submission and its side effects — is identical and lives in
// sendMessage, so the two entry points can never drift on the auth/abuse rules
// again (the prior drift is audit finding #156).
type sendVariant struct {
	auditAction string // "mail.send" or "mail.batch_send"
	batch       bool   // true → increment BatchMessagesSent and set webhook "batch":true
}

// sendOutcome is the rendered result of one send attempt, in a form both the
// HTTP single-send handler (status + error envelope) and the per-message batch
// handler (code/error fields) can consume. A zero code means success.
type sendOutcome struct {
	messageID  string
	httpStatus int    // 200 on success; the appropriate 4xx/5xx on failure
	code       string // error code, "" on success
	message    string // human-readable error, "" on success
}

func sendOK(messageID string) sendOutcome {
	return sendOutcome{messageID: messageID, httpStatus: http.StatusOK}
}

func sendErr(status int, code, message string) sendOutcome {
	return sendOutcome{httpStatus: status, code: code, message: message}
}

// handleSend accepts a JSON email payload, validates it, and submits to Postfix.
// Requires API key or session auth. Enforces domain ownership. The heavy lifting
// is shared with the batch endpoint via sendMessage.
func (s *Server) handleSend(w http.ResponseWriter, r *http.Request) {
	var req sendRequest
	if err := decodeJSON(r, &req); err != nil {
		respondError(w, r, http.StatusBadRequest, "INVALID_JSON", "Invalid JSON request body")
		return
	}

	adminID := getAdminID(r.Context())
	adminRole := getAdminRole(r.Context())
	apiKeyID := getAPIKeyID(r.Context())
	ip := clientIP(r)

	out := s.sendMessage(r, req, adminID, adminRole, apiKeyID, ip, sendVariant{auditAction: "mail.send"})
	if out.code != "" {
		respondError(w, r, out.httpStatus, out.code, out.message)
		return
	}
	respond(w, r, http.StatusOK, sendResponse{MessageID: out.messageID})
}

// sendMessage runs the full outbound pipeline for a single message: required-field
// validation, sender-domain authorization (API-key scoping + RBAC), abuse control
// (suspension/rate/spike), the SMTP submission, and the post-send side effects
// (metrics, message storage, domain stats, audit, webhook). It performs no HTTP
// I/O itself — it returns a sendOutcome the caller renders — so handleSend and
// handleBatchSend share one authoritative copy of the rules.
//
// The auth/abuse caller context (adminID, adminRole, apiKeyID, ip) is resolved
// once by the caller and passed in: the batch handler resolves it a single time
// for the whole request rather than re-reading it per message.
func (s *Server) sendMessage(r *http.Request, req sendRequest, adminID, adminRole, apiKeyID, ip string, v sendVariant) sendOutcome {
	ctx := r.Context()

	// Validate required fields.
	if req.From.Email == "" {
		return sendErr(http.StatusBadRequest, "MISSING_FIELDS", "from.email is required")
	}
	if len(req.To) == 0 {
		return sendErr(http.StatusBadRequest, "MISSING_FIELDS", "at least one recipient in 'to' is required")
	}
	for i, a := range req.To {
		if a.Email == "" {
			return sendErr(http.StatusBadRequest, "MISSING_FIELDS", fmt.Sprintf("to[%d].email is required", i))
		}
	}
	if req.Subject == "" {
		return sendErr(http.StatusBadRequest, "MISSING_FIELDS", "subject is required")
	}
	if req.TextBody == "" && req.HTMLBody == "" {
		return sendErr(http.StatusBadRequest, "MISSING_FIELDS", "text_body or html_body is required")
	}

	// Validate sender domain — must be a domain managed by Vectis.
	senderDomain := extractDomain(req.From.Email)
	if senderDomain == "" {
		return sendErr(http.StatusBadRequest, "INVALID_SENDER", "Invalid sender email address")
	}

	domain, err := s.domains.GetByName(ctx, senderDomain)
	if err != nil {
		s.logger.Error("domain lookup failed", "error", err)
		return sendErr(http.StatusInternalServerError, "INTERNAL_ERROR", "Failed to verify sender domain")
	}
	if domain == nil {
		return sendErr(http.StatusForbidden, "DOMAIN_NOT_FOUND",
			"Sender domain '"+senderDomain+"' is not managed by this server")
	}
	if !domain.Active {
		return sendErr(http.StatusForbidden, "DOMAIN_INACTIVE",
			"Sender domain '"+senderDomain+"' is inactive")
	}

	// Authorize the sender domain: API-key scoping first (specific code), then
	// RBAC. These are the two halves of canAccessDomain, split so a scoped-key
	// violation reports API_KEY_DOMAIN_SCOPE rather than a generic FORBIDDEN.
	if !s.apiKeyAllowsDomain(ctx, domain.ID) {
		return sendErr(http.StatusForbidden, "API_KEY_DOMAIN_SCOPE",
			"This API key does not have access to domain '"+senderDomain+"'")
	}
	if !auth.CanAccessAllDomains(adminRole) {
		ok, _ := s.adminDomains.HasAccess(ctx, adminID, domain.ID)
		if !ok {
			return sendErr(http.StatusForbidden, "FORBIDDEN",
				"You do not have access to send from domain '"+senderDomain+"'")
		}
	}

	// Abuse detection: check sender mailbox suspension and rate limits.
	senderLocalPart := extractLocalPart(req.From.Email)
	if senderLocalPart != "" {
		mailbox, _ := s.mailboxes.GetByEmail(ctx, domain.ID, senderLocalPart)
		if mailbox != nil {
			// Check if mailbox is suspended from sending.
			suspended, reason, _ := s.abuseEvents.IsMailboxSuspended(ctx, mailbox.ID)
			if suspended {
				return sendErr(http.StatusForbidden, "MAILBOX_SUSPENDED",
					"Sending suspended for this mailbox: "+reason)
			}

			// Rate check + spike detection.
			if s.abuseDetector != nil {
				check, err := s.abuseDetector.CheckAndRecord(ctx, mailbox.ID, domain.ID)
				if err != nil {
					s.logger.Error("abuse check failed", "error", err)
					// Fail open — don't block sending on abuse check errors.
				} else if !check.Allowed {
					// Auto-suspend the mailbox.
					s.abuseEvents.SuspendMailbox(ctx, mailbox.ID, check.Reason)
					action := "suspend"
					s.abuseEvents.LogEvent(ctx, &domain.ID, &mailbox.ID, "auto_suspend", "critical",
						map[string]any{"reason": check.Reason, "hourly_count": check.MailboxCount}, &action)

					vectismetrics.EmailsSendSuspended.Inc()
					return sendErr(http.StatusTooManyRequests, "RATE_LIMIT_EXCEEDED", check.Reason)
				} else if check.SpikeDetected {
					// Log spike alert but allow the send.
					action := "alert"
					s.abuseEvents.LogEvent(ctx, &domain.ID, &mailbox.ID, "rate_spike", "warn",
						map[string]any{"mailbox_hourly": check.MailboxCount, "domain_hourly": check.DomainCount}, &action)
				}
			}
		}
	}

	// Validate custom headers — only X-* allowed.
	for k := range req.Headers {
		if !strings.HasPrefix(k, "X-") {
			return sendErr(http.StatusBadRequest, "INVALID_HEADER",
				"Custom headers must start with 'X-': "+k)
		}
	}

	// Check mail sender is initialized.
	if s.mailSender == nil {
		return sendErr(http.StatusServiceUnavailable, "SEND_UNAVAILABLE",
			"Sending is not configured on this server")
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
		// Header-injection attempts are client errors, not server faults.
		if errors.Is(err, mail.ErrHeaderInjection) {
			s.logger.Warn("send rejected: header injection", "error", err, "from", req.From.Email)
			return sendErr(http.StatusBadRequest, "INVALID_HEADER",
				"Message rejected: a header field contains illegal characters")
		}
		s.logger.Error("send failed", "error", err, "from", req.From.Email)
		return sendErr(http.StatusInternalServerError, "SEND_FAILED",
			"Failed to send message: "+err.Error())
	}

	vectismetrics.EmailsSent.Inc()
	if v.batch {
		vectismetrics.BatchMessagesSent.Inc()
	}

	// Store message metadata.
	if s.messages != nil {
		s.messages.Create(ctx, &repository.Message{
			DomainID:   domain.ID,
			MessageID:  result.MessageID,
			Direction:  "outbound",
			Sender:     req.From.Email,
			Recipients: allRecipients(req.To, req.CC, req.BCC),
			Subject:    req.Subject,
			Status:     "sent",
			CreatedAt:  time.Now().UTC(),
		})
	}

	// Increment domain stats.
	if s.mailStats != nil {
		s.mailStats.Increment(ctx, domain.ID, "sent", 0)
	}

	// Audit log.
	s.audit.Log(ctx, &adminID, v.auditAction, "domain", &domain.ID,
		map[string]any{
			"message_id": result.MessageID,
			"from":       req.From.Email,
			"to_count":   len(req.To),
			"subject":    req.Subject,
			"api_key":    apiKeyID != "",
		}, &ip)

	// Fire mail.sent webhook event.
	if s.webhookDispatcher != nil {
		toEmails := make([]string, len(req.To))
		for i, a := range req.To {
			toEmails[i] = a.Email
		}
		data := map[string]any{
			"message_id": result.MessageID,
			"from":       req.From.Email,
			"to":         toEmails,
			"subject":    req.Subject,
			"domain":     senderDomain,
		}
		if v.batch {
			data["batch"] = true
		}
		s.webhookDispatcher.Dispatch(ctx, domain.ID, mail.WebhookEvent{
			ID:        result.MessageID,
			Event:     "mail.sent",
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Data:      data,
		})
	}

	return sendOK(result.MessageID)
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
