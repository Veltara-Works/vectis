package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	stdmail "net/mail"
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

	// Detect RFC 5965 feedback-loop complaints (ARF). If the inbound is an
	// ISP complaint report about one of our outbound messages, record it in
	// fbl_reports and fire mail.complained. This runs in its own goroutine
	// because the parse + lookup is cheap but independent of the main
	// response path.
	if notif.RawMessageB64 != "" {
		go s.handleARFComplaint(domain.ID, notif)
	}

	respond(w, r, http.StatusOK, map[string]string{"status": "processed"})
}

// handleARFComplaint inspects an inbound message to see if it's a
// feedback-loop complaint (RFC 5965). If so, it links the complaint back to
// one of our outbound messages / mailboxes where possible, stores it in
// fbl_reports, and dispatches a mail.complained webhook keyed to the
// originating domain (not the domain the complaint was addressed to).
func (s *Server) handleARFComplaint(deliveredDomainID string, notif inboundNotification) {
	raw, err := base64.StdEncoding.DecodeString(notif.RawMessageB64)
	if err != nil {
		return
	}

	// Quick check on the outer Content-Type before doing a full parse.
	msg, err := stdmail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return
	}
	if !mail.IsARFReport(msg.Header.Get("Content-Type")) {
		return
	}

	report, err := mail.ParseARF(raw)
	if err != nil {
		s.logger.Warn("arf parse failed", "error", err, "message_id", notif.MessageID)
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Try to attribute the complaint to one of our managed domains (the
	// originating domain, not the complainer's ISP domain).
	var (
		originDomainID  *string
		originMailboxID *string
	)
	if report.ReportedDomain != "" {
		if d, err := s.domains.GetByName(ctx, report.ReportedDomain); err == nil && d != nil {
			originDomainID = &d.ID
			// Link to mailbox if the original sender matches one of ours.
			if report.OriginalMailFrom != "" {
				local := extractLocalPart(report.OriginalMailFrom)
				if local != "" {
					if mb, _ := s.mailboxes.GetByEmail(ctx, d.ID, local); mb != nil {
						originMailboxID = &mb.ID
					}
				}
			}
		}
	}

	// Persist the report. Details JSON carries every machine-readable field
	// verbatim so we can audit later without reparsing.
	detailsJSON, _ := json.Marshal(report.Raw)
	var originalMsgID *string
	if report.OriginalMessageID != "" {
		v := report.OriginalMessageID
		originalMsgID = &v
	}
	var feedbackID *string
	if fid, ok := report.Raw["feedback-id"]; ok && fid != "" {
		feedbackID = &fid
	}
	if _, err := s.fblReports.Create(ctx, &repository.FBLReport{
		DomainID:          originDomainID,
		MailboxID:         originMailboxID,
		OriginalMessageID: originalMsgID,
		ReporterDomain:    report.ReportingMTA,
		ComplaintType:     mail.ComplaintTypeForDB(report.FeedbackType),
		FeedbackID:        feedbackID,
		Details:           detailsJSON,
	}); err != nil {
		s.logger.Error("store fbl report failed", "error", err, "message_id", notif.MessageID)
		// Still try to fire the webhook — the ISP complaint matters even if
		// our storage layer hiccups.
	}

	vectismetrics.FBLComplaints.Inc()

	if s.webhookDispatcher == nil {
		return
	}

	// Dispatch target: prefer the origin domain (subscribers to that domain
	// care about complaints against their mail). Fall back to the domain
	// that received the complaint so it isn't silently dropped.
	dispatchDomainID := deliveredDomainID
	if originDomainID != nil {
		dispatchDomainID = *originDomainID
	}

	payload := map[string]any{
		"feedback_type":       report.FeedbackType,
		"complaint_type":      mail.ComplaintTypeForDB(report.FeedbackType),
		"original_mail_from":  report.OriginalMailFrom,
		"original_rcpt_to":    report.OriginalRcptTo,
		"original_message_id": report.OriginalMessageID,
		"reported_domain":     report.ReportedDomain,
		"source_ip":           report.SourceIP,
		"reporting_mta":       report.ReportingMTA,
		"user_agent":          report.UserAgent,
		"arrival_date":        report.ArrivalDate,
	}

	s.webhookDispatcher.Dispatch(ctx, dispatchDomainID, mail.WebhookEvent{
		ID:        notif.MessageID,
		Event:     "mail.complained",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Data:      payload,
	})
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
