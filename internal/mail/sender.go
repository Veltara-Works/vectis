package mail

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

// Sender submits outbound messages to Postfix via SMTP on the internal network.
type Sender struct {
	host   string // e.g. "vectis-postfix"
	port   string // e.g. "25"
	ehlo   string // EHLO hostname
	logger *slog.Logger
}

// NewSender creates a mail sender that submits to Postfix.
// smtpAddr is "host:port" (e.g. "vectis-postfix:25").
func NewSender(smtpAddr, ehlo string, logger *slog.Logger) *Sender {
	host, port, err := net.SplitHostPort(smtpAddr)
	if err != nil {
		host = smtpAddr
		port = "25"
	}
	return &Sender{host: host, port: port, ehlo: ehlo, logger: logger}
}

// Message represents an outbound email to be sent.
type Message struct {
	From        Address      `json:"from"`
	To          []Address    `json:"to"`
	CC          []Address    `json:"cc,omitempty"`
	BCC         []Address    `json:"bcc,omitempty"`
	ReplyTo     *Address     `json:"reply_to,omitempty"`
	Subject     string       `json:"subject"`
	TextBody    string       `json:"text_body,omitempty"`
	HTMLBody    string       `json:"html_body,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"` // custom headers (X-*)
	// MessageID, when non-empty, is used verbatim as the RFC 5322 Message-ID.
	// Callers pre-generate this (via GenerateMessageID) when they need to
	// reference the ID before submission — e.g., to stamp tracking tokens
	// into the HTML body. If empty, Sender generates one.
	MessageID string `json:"-"`
}

// Address is an email address with optional display name.
type Address struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email"`
}

// Attachment is a base64-encoded file attachment.
type Attachment struct {
	Filename    string `json:"filename"`
	ContentType string `json:"content_type"`
	Content     string `json:"content"` // base64-encoded
}

// SendResult contains the result of a send operation.
type SendResult struct {
	MessageID string `json:"message_id"`
}

// String formats the address as "Name <email>" or just "email".
func (a Address) String() string {
	if a.Name != "" {
		return mime.QEncoding.Encode("utf-8", a.Name) + " <" + a.Email + ">"
	}
	return a.Email
}

// Send submits a message to Postfix and returns the generated message ID.
func (s *Sender) Send(msg *Message) (*SendResult, error) {
	messageID := msg.MessageID
	if messageID == "" {
		messageID = GenerateMessageID(s.ehlo)
	}

	// Build RFC 5322 message.
	raw, err := buildMessage(msg, messageID, s.ehlo)
	if err != nil {
		return nil, fmt.Errorf("build message: %w", err)
	}

	// Collect all recipients.
	var rcpts []string
	for _, a := range msg.To {
		rcpts = append(rcpts, a.Email)
	}
	for _, a := range msg.CC {
		rcpts = append(rcpts, a.Email)
	}
	for _, a := range msg.BCC {
		rcpts = append(rcpts, a.Email)
	}

	// Connect and send via SMTP (no auth — internal trusted network).
	addr := net.JoinHostPort(s.host, s.port)
	c, err := smtp.Dial(addr)
	if err != nil {
		return nil, fmt.Errorf("smtp dial %s: %w", addr, err)
	}
	defer c.Close()

	if err := c.Hello(s.ehlo); err != nil {
		return nil, fmt.Errorf("smtp ehlo: %w", err)
	}
	if err := c.Mail(msg.From.Email); err != nil {
		return nil, fmt.Errorf("smtp mail from: %w", err)
	}
	for _, rcpt := range rcpts {
		if err := c.Rcpt(rcpt); err != nil {
			return nil, fmt.Errorf("smtp rcpt %s: %w", rcpt, err)
		}
	}

	wc, err := c.Data()
	if err != nil {
		return nil, fmt.Errorf("smtp data: %w", err)
	}
	if _, err := wc.Write(raw); err != nil {
		wc.Close()
		return nil, fmt.Errorf("smtp write: %w", err)
	}
	if err := wc.Close(); err != nil {
		return nil, fmt.Errorf("smtp close data: %w", err)
	}
	if err := c.Quit(); err != nil {
		// Non-fatal — message was already accepted.
		s.logger.Debug("smtp quit error (non-fatal)", "error", err)
	}

	s.logger.Info("message sent",
		"message_id", messageID,
		"from", msg.From.Email,
		"to_count", len(msg.To),
		"subject", msg.Subject)

	return &SendResult{MessageID: messageID}, nil
}

// buildMessage creates an RFC 5322 message with optional MIME multipart.
func buildMessage(msg *Message, messageID, hostname string) ([]byte, error) {
	var buf bytes.Buffer

	// Headers.
	writeHeader(&buf, "Message-ID", "<"+messageID+">")
	writeHeader(&buf, "Date", time.Now().UTC().Format(time.RFC1123Z))
	writeHeader(&buf, "From", msg.From.String())
	writeHeader(&buf, "To", formatAddresses(msg.To))
	if len(msg.CC) > 0 {
		writeHeader(&buf, "Cc", formatAddresses(msg.CC))
	}
	if msg.ReplyTo != nil {
		writeHeader(&buf, "Reply-To", msg.ReplyTo.String())
	}
	writeHeader(&buf, "Subject", mime.QEncoding.Encode("utf-8", msg.Subject))
	writeHeader(&buf, "MIME-Version", "1.0")
	writeHeader(&buf, "X-Mailer", "Vectis Mail API")

	// Custom headers (only X-* allowed).
	for k, v := range msg.Headers {
		if strings.HasPrefix(k, "X-") {
			writeHeader(&buf, k, v)
		}
	}

	hasAttachments := len(msg.Attachments) > 0
	hasHTML := msg.HTMLBody != ""
	hasText := msg.TextBody != ""

	switch {
	case hasAttachments:
		// multipart/mixed → multipart/alternative (text + html) + attachments
		mixedWriter := multipart.NewWriter(&buf)
		writeHeader(&buf, "Content-Type", "multipart/mixed; boundary="+mixedWriter.Boundary())
		buf.WriteString("\r\n")

		// Body part (alternative if both text and html).
		if hasText && hasHTML {
			altHeader := make(textproto.MIMEHeader)
			altWriter := multipart.NewWriter(nil) // just for boundary
			altHeader.Set("Content-Type", "multipart/alternative; boundary="+altWriter.Boundary())
			bodyPart, _ := mixedWriter.CreatePart(altHeader)

			// Re-create with the bodyPart writer.
			altW := multipart.NewWriter(bodyPart)
			altW.SetBoundary(altWriter.Boundary())
			writeTextPart(altW, "text/plain", msg.TextBody)
			writeTextPart(altW, "text/html", msg.HTMLBody)
			altW.Close()
		} else if hasHTML {
			writeTextPartMixed(mixedWriter, "text/html", msg.HTMLBody)
		} else if hasText {
			writeTextPartMixed(mixedWriter, "text/plain", msg.TextBody)
		}

		// Attachments.
		for _, att := range msg.Attachments {
			if err := writeAttachment(mixedWriter, att); err != nil {
				return nil, err
			}
		}
		mixedWriter.Close()

	case hasText && hasHTML:
		// multipart/alternative.
		altWriter := multipart.NewWriter(&buf)
		writeHeader(&buf, "Content-Type", "multipart/alternative; boundary="+altWriter.Boundary())
		buf.WriteString("\r\n")
		writeTextPart(altWriter, "text/plain", msg.TextBody)
		writeTextPart(altWriter, "text/html", msg.HTMLBody)
		altWriter.Close()

	case hasHTML:
		writeHeader(&buf, "Content-Type", "text/html; charset=utf-8")
		writeHeader(&buf, "Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		buf.WriteString(msg.HTMLBody)

	default:
		writeHeader(&buf, "Content-Type", "text/plain; charset=utf-8")
		writeHeader(&buf, "Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		buf.WriteString(msg.TextBody)
	}

	return buf.Bytes(), nil
}

func writeHeader(buf *bytes.Buffer, key, value string) {
	buf.WriteString(key)
	buf.WriteString(": ")
	buf.WriteString(value)
	buf.WriteString("\r\n")
}

func formatAddresses(addrs []Address) string {
	parts := make([]string, len(addrs))
	for i, a := range addrs {
		parts[i] = a.String()
	}
	return strings.Join(parts, ", ")
}

func writeTextPart(w *multipart.Writer, contentType, body string) {
	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", contentType+"; charset=utf-8")
	h.Set("Content-Transfer-Encoding", "quoted-printable")
	part, _ := w.CreatePart(h)
	io.WriteString(part, body)
}

func writeTextPartMixed(w *multipart.Writer, contentType, body string) {
	writeTextPart(w, contentType, body)
}

func writeAttachment(w *multipart.Writer, att Attachment) error {
	data, err := base64.StdEncoding.DecodeString(att.Content)
	if err != nil {
		return fmt.Errorf("decode attachment %s: %w", att.Filename, err)
	}

	h := make(textproto.MIMEHeader)
	h.Set("Content-Type", att.ContentType+"; name=\""+att.Filename+"\"")
	h.Set("Content-Disposition", "attachment; filename=\""+att.Filename+"\"")
	h.Set("Content-Transfer-Encoding", "base64")

	part, err := w.CreatePart(h)
	if err != nil {
		return err
	}

	encoder := base64.NewEncoder(base64.StdEncoding, part)
	encoder.Write(data)
	encoder.Close()
	return nil
}

// GenerateMessageID returns a new RFC 5322 Message-ID local part (without
// angle brackets) rooted at hostname. Callers that need to reference the ID
// before submission (e.g. to stamp tracking tokens into the body) should
// generate it here and assign it to Message.MessageID.
func GenerateMessageID(hostname string) string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x.%d@%s",
		b, time.Now().UnixNano(), hostname)
}
