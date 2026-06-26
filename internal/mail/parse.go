package mail

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
)

// MIME parsing limits — defence against resource-exhaustion DoS from
// attacker-sent mail. Inbound messages are attacker-controlled, so the parser
// must bound recursion depth (deeply nested multiparts → stack), part count
// (CPU), and total accumulated bytes (memory), in addition to the per-part cap.
const (
	maxMIMEDepth      = 20       // max multipart nesting levels
	maxMIMEParts      = 1000     // max total parts across the whole message
	maxMIMEPartBytes  = 25 << 20 // max bytes read from a single part (25 MB)
	maxMIMETotalBytes = 64 << 20 // max bytes accumulated across all parts (64 MB)
)

// mimeBudget tracks cumulative parsing cost across the recursive multipart walk.
type mimeBudget struct {
	parts int
	bytes int
}

// ParsedMessage represents a fully parsed RFC 5322 email.
type ParsedMessage struct {
	MessageID   string             `json:"message_id"`
	From        Address            `json:"from"`
	To          []Address          `json:"to"`
	CC          []Address          `json:"cc,omitempty"`
	ReplyTo     *Address           `json:"reply_to,omitempty"`
	Subject     string             `json:"subject"`
	Date        string             `json:"date,omitempty"`
	BodyText    string             `json:"body_text,omitempty"`
	BodyHTML    string             `json:"body_html,omitempty"`
	Attachments []ParsedAttachment `json:"attachments,omitempty"`
	Headers     map[string]string  `json:"headers,omitempty"`
}

// ParsedAttachment represents an email attachment extracted from MIME.
type ParsedAttachment struct {
	Filename      string `json:"filename"`
	ContentType   string `json:"content_type"`
	Size          int    `json:"size"`
	ContentBase64 string `json:"content_base64"`
}

// ParseRawMessage parses a raw RFC 5322 message into structured fields.
func ParseRawMessage(raw []byte) (*ParsedMessage, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse message: %w", err)
	}

	parsed := &ParsedMessage{
		MessageID: strings.Trim(msg.Header.Get("Message-Id"), "<>"),
		Subject:   decodeHeader(msg.Header.Get("Subject")),
		Date:      msg.Header.Get("Date"),
		Headers:   extractHeaders(msg.Header),
	}

	// Parse From.
	if fromList, err := msg.Header.AddressList("From"); err == nil && len(fromList) > 0 {
		parsed.From = Address{Name: fromList[0].Name, Email: fromList[0].Address}
	} else {
		parsed.From = Address{Email: msg.Header.Get("From")}
	}

	// Parse To.
	if toList, err := msg.Header.AddressList("To"); err == nil {
		for _, a := range toList {
			parsed.To = append(parsed.To, Address{Name: a.Name, Email: a.Address})
		}
	}

	// Parse CC.
	if ccList, err := msg.Header.AddressList("Cc"); err == nil {
		for _, a := range ccList {
			parsed.CC = append(parsed.CC, Address{Name: a.Name, Email: a.Address})
		}
	}

	// Parse Reply-To.
	if rtList, err := msg.Header.AddressList("Reply-To"); err == nil && len(rtList) > 0 {
		parsed.ReplyTo = &Address{Name: rtList[0].Name, Email: rtList[0].Address}
	}

	// Parse body — handle multipart and single-part messages.
	contentType := msg.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "text/plain"
	}

	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		// Fallback: treat as plain text.
		body, _ := io.ReadAll(io.LimitReader(msg.Body, 10<<20)) // 10 MB limit
		parsed.BodyText = string(body)
		return parsed, nil
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		if err := parseMultipart(msg.Body, params["boundary"], parsed, &mimeBudget{}, 0); err != nil {
			// Fallback: raw body.
			body, _ := io.ReadAll(io.LimitReader(msg.Body, 10<<20))
			parsed.BodyText = string(body)
		}
	} else {
		body, _ := io.ReadAll(io.LimitReader(msg.Body, 10<<20))
		decoded := decodeTransferEncoding(body, msg.Header.Get("Content-Transfer-Encoding"))
		if strings.HasPrefix(mediaType, "text/html") {
			parsed.BodyHTML = string(decoded)
		} else {
			parsed.BodyText = string(decoded)
		}
	}

	return parsed, nil
}

func parseMultipart(body io.Reader, boundary string, parsed *ParsedMessage, budget *mimeBudget, depth int) error {
	if depth > maxMIMEDepth {
		// Refuse to recurse further — bounds stack/CPU from deeply nested MIME.
		return fmt.Errorf("mime nesting exceeds %d levels", maxMIMEDepth)
	}

	reader := multipart.NewReader(body, boundary)

	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read part: %w", err)
		}

		budget.parts++
		if budget.parts > maxMIMEParts || budget.bytes >= maxMIMETotalBytes {
			// Stop processing further parts — bounds total CPU/memory from
			// attacker-sent messages with huge part counts or total size.
			// What has already been parsed is kept.
			break
		}

		partContentType := part.Header.Get("Content-Type")
		if partContentType == "" {
			partContentType = "text/plain"
		}
		mediaType, params, _ := mime.ParseMediaType(partContentType)
		disposition := part.Header.Get("Content-Disposition")
		transferEncoding := part.Header.Get("Content-Transfer-Encoding")

		// Nested multipart (e.g. multipart/alternative inside multipart/mixed).
		if strings.HasPrefix(mediaType, "multipart/") {
			nestedBoundary := params["boundary"]
			if nestedBoundary != "" {
				parseMultipart(part, nestedBoundary, parsed, budget, depth+1)
			}
			continue
		}

		// Per-part cap, further clamped by the remaining cumulative budget so a
		// flood of large parts cannot exceed maxMIMETotalBytes in aggregate.
		readCap := maxMIMEPartBytes
		if remaining := maxMIMETotalBytes - budget.bytes; remaining < readCap {
			readCap = remaining
		}
		content, _ := io.ReadAll(io.LimitReader(part, int64(readCap)))
		budget.bytes += len(content)
		decoded := decodeTransferEncoding(content, transferEncoding)

		// Check if this is an attachment.
		filename := part.FileName()
		if filename == "" && disposition != "" {
			_, dispParams, _ := mime.ParseMediaType(disposition)
			filename = dispParams["filename"]
		}

		if filename != "" || (disposition != "" && strings.HasPrefix(disposition, "attachment")) {
			// Attachment.
			if filename == "" {
				filename = "unnamed"
			}
			parsed.Attachments = append(parsed.Attachments, ParsedAttachment{
				Filename:      filename,
				ContentType:   mediaType,
				Size:          len(decoded),
				ContentBase64: base64.StdEncoding.EncodeToString(decoded),
			})
			continue
		}

		// Inline text/html body.
		switch {
		case strings.HasPrefix(mediaType, "text/html"):
			if parsed.BodyHTML == "" {
				parsed.BodyHTML = string(decoded)
			}
		case strings.HasPrefix(mediaType, "text/plain"):
			if parsed.BodyText == "" {
				parsed.BodyText = string(decoded)
			}
		default:
			// Unknown inline part — treat as attachment.
			parsed.Attachments = append(parsed.Attachments, ParsedAttachment{
				Filename:      filename,
				ContentType:   mediaType,
				Size:          len(decoded),
				ContentBase64: base64.StdEncoding.EncodeToString(decoded),
			})
		}
	}

	return nil
}

func decodeTransferEncoding(data []byte, encoding string) []byte {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(
			strings.Join(strings.Fields(string(data)), ""))
		if err != nil {
			return data // return raw on decode failure
		}
		return decoded
	case "quoted-printable":
		return decodeQuotedPrintable(data)
	default:
		return data
	}
}

func decodeQuotedPrintable(data []byte) []byte {
	var buf bytes.Buffer
	lines := bytes.Split(data, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimRight(line, "\r")
		// Soft line break.
		if bytes.HasSuffix(line, []byte("=")) {
			line = line[:len(line)-1]
			buf.Write(decodeQPLine(line))
			continue
		}
		buf.Write(decodeQPLine(line))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func decodeQPLine(line []byte) []byte {
	var buf bytes.Buffer
	for i := 0; i < len(line); i++ {
		if line[i] == '=' && i+2 < len(line) {
			hi := unhex(line[i+1])
			lo := unhex(line[i+2])
			if hi >= 0 && lo >= 0 {
				buf.WriteByte(byte(hi<<4 | lo))
				i += 2
				continue
			}
		}
		buf.WriteByte(line[i])
	}
	return buf.Bytes()
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	}
	return -1
}

func extractHeaders(h mail.Header) map[string]string {
	interesting := []string{
		"Date", "Reply-To", "In-Reply-To", "References",
		"X-Mailer", "User-Agent", "List-Unsubscribe",
		"X-Spam-Score", "X-Spam-Action", "X-Spamd-Result",
		"DKIM-Signature", "Authentication-Results",
		"Content-Type", "MIME-Version",
	}
	result := make(map[string]string)
	for _, key := range interesting {
		if val := h.Get(key); val != "" {
			result[key] = val
		}
	}
	return result
}

func decodeHeader(s string) string {
	dec := new(mime.WordDecoder)
	decoded, err := dec.DecodeHeader(s)
	if err != nil {
		return s
	}
	return decoded
}
