package mail

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"
)

// ErrHeaderInjection is returned when a message field that is written into an
// RFC 5322 header (or a MIME parameter) contains a CR or LF — i.e. an attempt
// to smuggle additional headers (header injection, e.g. an extra Bcc) or to
// split the message.
var ErrHeaderInjection = errors.New("mail: header injection attempt (CR/LF in header field)")

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
	From        Address           `json:"from"`
	To          []Address         `json:"to"`
	CC          []Address         `json:"cc,omitempty"`
	BCC         []Address         `json:"bcc,omitempty"`
	ReplyTo     *Address          `json:"reply_to,omitempty"`
	Subject     string            `json:"subject"`
	TextBody    string            `json:"text_body,omitempty"`
	HTMLBody    string            `json:"html_body,omitempty"`
	Attachments []Attachment      `json:"attachments,omitempty"`
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

// validateHeaders rejects any header-bound field containing CR or LF (header
// injection). Address Name and Subject are RFC 2047 Q-encoded downstream — which
// itself neutralises CR/LF — but they are validated here too as defence in
// depth. Body fields (TextBody/HTMLBody) are exempt: they are quoted-printable
// encoded and cannot break out of their MIME part. Attachment filenames are also
// checked for the '"' that would break the quoted MIME name/filename parameter.
func (m *Message) validateHeaders() error {
	noCRLF := func(field, v string) error {
		if strings.ContainsAny(v, "\r\n") {
			return fmt.Errorf("%w: %s", ErrHeaderInjection, field)
		}
		return nil
	}
	addrs := func(label string, list []Address) error {
		for i, a := range list {
			if err := noCRLF(fmt.Sprintf("%s[%d].email", label, i), a.Email); err != nil {
				return err
			}
			if err := noCRLF(fmt.Sprintf("%s[%d].name", label, i), a.Name); err != nil {
				return err
			}
		}
		return nil
	}
	if err := noCRLF("from.email", m.From.Email); err != nil {
		return err
	}
	if err := noCRLF("from.name", m.From.Name); err != nil {
		return err
	}
	for _, g := range []struct {
		label string
		list  []Address
	}{{"to", m.To}, {"cc", m.CC}, {"bcc", m.BCC}} {
		if err := addrs(g.label, g.list); err != nil {
			return err
		}
	}
	if m.ReplyTo != nil {
		if err := noCRLF("reply_to.email", m.ReplyTo.Email); err != nil {
			return err
		}
		if err := noCRLF("reply_to.name", m.ReplyTo.Name); err != nil {
			return err
		}
	}
	if err := noCRLF("subject", m.Subject); err != nil {
		return err
	}
	for k, v := range m.Headers {
		if err := noCRLF("header.key", k); err != nil {
			return err
		}
		if err := noCRLF("header["+k+"]", v); err != nil {
			return err
		}
	}
	for i, att := range m.Attachments {
		if err := noCRLF(fmt.Sprintf("attachments[%d].filename", i), att.Filename); err != nil {
			return err
		}
		if strings.Contains(att.Filename, `"`) {
			return fmt.Errorf("%w: attachments[%d].filename contains quote", ErrHeaderInjection, i)
		}
		if err := noCRLF(fmt.Sprintf("attachments[%d].content_type", i), att.ContentType); err != nil {
			return err
		}
	}
	return nil
}

// buildMessage creates an RFC 5322 message with optional MIME multipart.
func buildMessage(msg *Message, messageID, hostname string) ([]byte, error) {
	if err := msg.validateHeaders(); err != nil {
		return nil, err
	}

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
		if err := writeQuotedPrintable(&buf, msg.HTMLBody); err != nil {
			return nil, err
		}

	default:
		writeHeader(&buf, "Content-Type", "text/plain; charset=utf-8")
		writeHeader(&buf, "Content-Transfer-Encoding", "quoted-printable")
		buf.WriteString("\r\n")
		if err := writeQuotedPrintable(&buf, msg.TextBody); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func writeHeader(buf *bytes.Buffer, key, value string) {
	// Defence in depth: buildMessage validates all caller-supplied fields via
	// validateHeaders before reaching here, but strip any stray CR/LF so a
	// future caller that bypasses validation can never inject a header.
	buf.WriteString(stripCRLF(key))
	buf.WriteString(": ")
	buf.WriteString(stripCRLF(value))
	buf.WriteString("\r\n")
}

// stripCRLF removes carriage returns and line feeds, the characters used for
// header injection. Program-generated headers never legitimately contain them.
func stripCRLF(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
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
	_ = writeQuotedPrintable(part, body)
}

// writeQuotedPrintable encodes body per RFC 2045 §6.7 and writes it to w.
// The QP encoder escapes literal '=' to '=3D' and wraps lines at 76 chars,
// which is required whenever a part declares
// Content-Transfer-Encoding: quoted-printable.
func writeQuotedPrintable(w io.Writer, body string) error {
	enc := quotedprintable.NewWriter(w)
	if _, err := io.WriteString(enc, body); err != nil {
		return err
	}
	return enc.Close()
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
