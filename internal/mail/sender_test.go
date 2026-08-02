package mail

import (
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"strings"
	"testing"
)

// TestBuildMessage_QuotedPrintable_URLWithEquals reproduces the ValidonX P0:
// an outbound HTML body containing a URL with `=` in query parameters must be
// QP-encoded before transmission, otherwise standards-compliant clients
// greedily decode `=XY` sequences and eat adjacent characters.
func TestBuildMessage_QuotedPrintable_URLWithEquals(t *testing.T) {
	htmlBody := `<a href="https://validonx.com/verify-email-change?expires=1776839908&hash=abc123&id=2&signature=xyz789">verify</a>`
	msg := &Message{
		From:     Address{Email: "noreply@vectismail.com"},
		To:       []Address{{Email: "user@example.com"}},
		Subject:  "Verify",
		HTMLBody: htmlBody,
	}

	raw, err := buildMessage(msg, "msgid@host", "host")
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	rawStr := string(raw)

	// Transport form must not contain the verbatim `href="https:` because that
	// would mean `=` was left raw. Every literal `=` in the body must be
	// escaped to `=3D`.
	if strings.Contains(rawStr, `href="https`) {
		t.Errorf("transport body contains raw `href=\"https` — `=` was not QP-escaped.\nraw:\n%s", rawStr)
	}
	if !strings.Contains(rawStr, "href=3D") {
		t.Errorf("expected `href=3D` in QP-encoded body, not found.\nraw:\n%s", rawStr)
	}

	// Round-trip: parse the message, decode the body, confirm we recover the
	// original HTML byte-for-byte.
	parsed, err := mail.ReadMessage(strings.NewReader(rawStr))
	if err != nil {
		t.Fatalf("mail.ReadMessage: %v", err)
	}
	cte := parsed.Header.Get("Content-Transfer-Encoding")
	if cte != "quoted-printable" {
		t.Fatalf("Content-Transfer-Encoding = %q, want quoted-printable", cte)
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(parsed.Body))
	if err != nil {
		t.Fatalf("qp decode: %v", err)
	}
	if string(decoded) != htmlBody {
		t.Errorf("decoded body mismatch\n got: %q\nwant: %q", string(decoded), htmlBody)
	}
}

// TestBuildMessage_QuotedPrintable_PlainText covers the text-only branch.
func TestBuildMessage_QuotedPrintable_PlainText(t *testing.T) {
	body := "Click: https://example.com/verify?token=abc&id=42"
	msg := &Message{
		From:     Address{Email: "a@x"},
		To:       []Address{{Email: "b@y"}},
		Subject:  "t",
		TextBody: body,
	}
	raw, err := buildMessage(msg, "id@h", "h")
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	decoded, err := io.ReadAll(quotedprintable.NewReader(parsed.Body))
	if err != nil {
		t.Fatalf("qp decode: %v", err)
	}
	if string(decoded) != body {
		t.Errorf("round-trip mismatch\n got: %q\nwant: %q", string(decoded), body)
	}
}

// TestBuildMessage_QuotedPrintable_Multipart covers multipart/alternative
// (both text and HTML parts). Each part must be independently QP-encoded.
func TestBuildMessage_QuotedPrintable_Multipart(t *testing.T) {
	text := "token=abc id=42"
	html := `<p><a href="https://x.y/z?k=v&n=1">click</a></p>`
	msg := &Message{
		From:     Address{Email: "a@x"},
		To:       []Address{{Email: "b@y"}},
		Subject:  "t",
		TextBody: text,
		HTMLBody: html,
	}
	raw, err := buildMessage(msg, "id@h", "h")
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}

	// Assert the CTE header is declared on both parts, and that the literal
	// transport body contains the QP-escaped `=3D`, not a raw `=`.
	rawStr := string(raw)
	if strings.Count(rawStr, "Content-Transfer-Encoding: quoted-printable") != 2 {
		t.Errorf("expected QP CTE declared on both parts\nraw:\n%s", rawStr)
	}
	if !strings.Contains(rawStr, "token=3Dabc id=3D42") {
		t.Errorf("text part not QP-encoded in transport bytes\nraw:\n%s", rawStr)
	}
	if !strings.Contains(rawStr, `href=3D"https://x.y/z?k=3Dv&n=3D1"`) {
		t.Errorf("html part not QP-encoded in transport bytes\nraw:\n%s", rawStr)
	}

	parsed, err := mail.ReadMessage(strings.NewReader(rawStr))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	if mediaType != "multipart/alternative" {
		t.Fatalf("top-level media type = %q, want multipart/alternative", mediaType)
	}

	// multipart.Part auto-decodes QP bodies and strips the CTE header — read
	// the part directly and verify the round-tripped content matches what was
	// supplied.
	mr := multipart.NewReader(parsed.Body, params["boundary"])
	var gotText, gotHTML string
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		body, err := io.ReadAll(p)
		if err != nil {
			t.Fatalf("read part: %v", err)
		}
		ct := p.Header.Get("Content-Type")
		switch {
		case strings.HasPrefix(ct, "text/plain"):
			gotText = string(body)
		case strings.HasPrefix(ct, "text/html"):
			gotHTML = string(body)
		}
	}
	if gotText != text {
		t.Errorf("text part\n got: %q\nwant: %q", gotText, text)
	}
	if gotHTML != html {
		t.Errorf("html part\n got: %q\nwant: %q", gotHTML, html)
	}
}

// TestBuildMessage_HeaderInjection verifies that CR/LF (and quote-in-filename)
// in any header-bound field is rejected, preventing SMTP/RFC 5322 header
// injection (e.g. smuggling an extra Bcc). Body fields are exempt.
func TestBuildMessage_HeaderInjection(t *testing.T) {
	base := func() *Message {
		return &Message{
			From:     Address{Email: "noreply@vectismail.com"},
			To:       []Address{{Email: "user@example.com"}},
			Subject:  "Hi",
			TextBody: "body",
		}
	}

	mutate := []struct {
		name string
		mod  func(*Message)
	}{
		{"from email CRLF", func(m *Message) { m.From.Email = "a@b.com\r\nBcc: evil@x.com" }},
		{"to email LF", func(m *Message) { m.To[0].Email = "u@e.com\nBcc: evil@x.com" }},
		{"cc email CRLF", func(m *Message) { m.CC = []Address{{Email: "c@e.com\r\nX-Evil: 1"}} }},
		{"bcc email CRLF", func(m *Message) { m.BCC = []Address{{Email: "b@e.com\r\nX-Evil: 1"}} }},
		{"reply-to CRLF", func(m *Message) { m.ReplyTo = &Address{Email: "r@e.com\r\nX-Evil: 1"} }},
		{"name CRLF", func(m *Message) { m.From.Name = "Bob\r\nBcc: evil@x.com" }},
		{"subject CRLF", func(m *Message) { m.Subject = "Hi\r\nBcc: evil@x.com" }},
		{"custom header value CRLF", func(m *Message) { m.Headers = map[string]string{"X-Foo": "v\r\nBcc: evil@x.com"} }},
		{"custom header key CRLF", func(m *Message) { m.Headers = map[string]string{"X-Foo\r\nBcc: evil@x.com": "v"} }},
		{"attachment filename CRLF", func(m *Message) {
			m.Attachments = []Attachment{{Filename: "f\r\nBcc: evil@x.com", ContentType: "text/plain", Content: "aGk="}}
		}},
		{"attachment filename quote", func(m *Message) {
			m.Attachments = []Attachment{{Filename: `f"; x="y`, ContentType: "text/plain", Content: "aGk="}}
		}},
		{"attachment content_type CRLF", func(m *Message) {
			m.Attachments = []Attachment{{Filename: "f.txt", ContentType: "text/plain\r\nBcc: evil@x.com", Content: "aGk="}}
		}},
		{"attachment content_type quote", func(m *Message) {
			m.Attachments = []Attachment{{Filename: "f.txt", ContentType: `text/plain"; evil="x`, Content: "aGk="}}
		}},
		{"attachment content_type semicolon param smuggling", func(m *Message) {
			m.Attachments = []Attachment{{Filename: "f.txt", ContentType: "text/plain; charset=x; boundary=y", Content: "aGk="}}
		}},
	}
	for _, tc := range mutate {
		t.Run(tc.name, func(t *testing.T) {
			m := base()
			tc.mod(m)
			if _, err := buildMessage(m, "id@host", "host"); err == nil {
				t.Fatalf("expected header-injection rejection, got nil error")
			}
		})
	}

	// A legitimate message with no CR/LF must still build successfully.
	if _, err := buildMessage(base(), "id@host", "host"); err != nil {
		t.Fatalf("clean message rejected: %v", err)
	}
}

// pngPixel is a 1x1 PNG, base64-encoded — a realistic inline image payload.
const pngPixel = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="

// walkParts returns every part in a multipart body, descending into nested
// multiparts, as (mediaType, header) pairs.
func walkParts(t *testing.T, r io.Reader, boundary string) []struct {
	MediaType string
	Header    textproto.MIMEHeader
} {
	t.Helper()
	var out []struct {
		MediaType string
		Header    textproto.MIMEHeader
	}
	mr := multipart.NewReader(r, boundary)
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("NextPart: %v", err)
		}
		mt, params, err := mime.ParseMediaType(p.Header.Get("Content-Type"))
		if err != nil {
			t.Fatalf("ParseMediaType(%q): %v", p.Header.Get("Content-Type"), err)
		}
		out = append(out, struct {
			MediaType string
			Header    textproto.MIMEHeader
		}{mt, p.Header})
		if strings.HasPrefix(mt, "multipart/") {
			out = append(out, walkParts(t, p, params["boundary"])...)
		}
	}
	return out
}

// TestBuildMessage_InlineAttachment_Related pins the fix for the Pharlux broken
// logo: an attachment carrying a ContentID must produce a multipart/related
// message with `Content-ID: <id>` and an inline disposition, so an HTML body
// can resolve `cid:<id>`. Previously the id was dropped and the image rendered
// broken, with the file arriving as a stray attachment.
func TestBuildMessage_InlineAttachment_Related(t *testing.T) {
	msg := &Message{
		From:     Address{Email: "noreply@pharlux.com"},
		To:       []Address{{Email: "buyer@example.com"}},
		Subject:  "welcome",
		TextBody: "plain",
		HTMLBody: `<img src="cid:pharlux-logo" alt="Pharlux">`,
		Attachments: []Attachment{{
			Filename:    "logo.png",
			ContentType: "image/png",
			Content:     pngPixel,
			ContentID:   "pharlux-logo",
		}},
	}

	raw, err := buildMessage(msg, "id@h", "h")
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}

	parsed, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	// With inline parts and no ordinary attachments, related is the top level —
	// NOT mixed, which would leave the cid: reference unresolvable in strict
	// clients.
	if mediaType != "multipart/related" {
		t.Fatalf("top-level media type = %q, want multipart/related", mediaType)
	}

	parts := walkParts(t, parsed.Body, params["boundary"])

	var foundImage bool
	for _, p := range parts {
		if p.MediaType != "image/png" {
			continue
		}
		foundImage = true
		if got := p.Header.Get("Content-ID"); got != "<pharlux-logo>" {
			t.Errorf("Content-ID = %q, want %q", got, "<pharlux-logo>")
		}
		if got := p.Header.Get("Content-Disposition"); !strings.HasPrefix(got, "inline") {
			t.Errorf("Content-Disposition = %q, want inline...", got)
		}
	}
	if !foundImage {
		t.Fatalf("no image/png part found; parts=%v", parts)
	}

	// The body must still be reachable as an alternative inside related.
	var foundAlt, foundHTML bool
	for _, p := range parts {
		switch p.MediaType {
		case "multipart/alternative":
			foundAlt = true
		case "text/html":
			foundHTML = true
		}
	}
	if !foundAlt || !foundHTML {
		t.Errorf("body layout wrong: alternative=%v html=%v", foundAlt, foundHTML)
	}
}

// TestBuildMessage_InlineAndRegularAttachment nests related inside mixed: the
// inline image must stay with the body it is referenced from, while an ordinary
// attachment remains a sibling under mixed.
func TestBuildMessage_InlineAndRegularAttachment(t *testing.T) {
	msg := &Message{
		From:     Address{Email: "a@x"},
		To:       []Address{{Email: "b@y"}},
		Subject:  "t",
		HTMLBody: `<img src="cid:logo">`,
		Attachments: []Attachment{
			{Filename: "logo.png", ContentType: "image/png", Content: pngPixel, ContentID: "logo"},
			{Filename: "invoice.pdf", ContentType: "application/pdf", Content: pngPixel},
		},
	}

	raw, err := buildMessage(msg, "id@h", "h")
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	parsed, err := mail.ReadMessage(strings.NewReader(string(raw)))
	if err != nil {
		t.Fatalf("ReadMessage: %v", err)
	}
	mediaType, params, err := mime.ParseMediaType(parsed.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("ParseMediaType: %v", err)
	}
	if mediaType != "multipart/mixed" {
		t.Fatalf("top-level media type = %q, want multipart/mixed", mediaType)
	}

	parts := walkParts(t, parsed.Body, params["boundary"])
	var hasRelated, hasPDF bool
	for _, p := range parts {
		switch p.MediaType {
		case "multipart/related":
			hasRelated = true
		case "application/pdf":
			hasPDF = true
			if got := p.Header.Get("Content-Disposition"); !strings.HasPrefix(got, "attachment") {
				t.Errorf("pdf Content-Disposition = %q, want attachment...", got)
			}
			if got := p.Header.Get("Content-ID"); got != "" {
				t.Errorf("ordinary attachment must have no Content-ID, got %q", got)
			}
		}
	}
	if !hasRelated || !hasPDF {
		t.Errorf("structure wrong: related=%v pdf=%v; parts=%v", hasRelated, hasPDF, parts)
	}
}

// TestBuildMessage_RegularAttachmentUnchanged is a regression guard: a message
// with only ordinary attachments must still be multipart/mixed with an
// attachment disposition and no Content-ID, exactly as before the inline work.
func TestBuildMessage_RegularAttachmentUnchanged(t *testing.T) {
	msg := &Message{
		From:        Address{Email: "a@x"},
		To:          []Address{{Email: "b@y"}},
		Subject:     "t",
		TextBody:    "hello",
		Attachments: []Attachment{{Filename: "f.pdf", ContentType: "application/pdf", Content: pngPixel}},
	}
	raw, err := buildMessage(msg, "id@h", "h")
	if err != nil {
		t.Fatalf("buildMessage: %v", err)
	}
	rawStr := string(raw)
	if !strings.Contains(rawStr, "multipart/mixed") {
		t.Errorf("want multipart/mixed\nraw:\n%s", rawStr)
	}
	if strings.Contains(rawStr, "multipart/related") {
		t.Errorf("no inline parts, so related must not appear\nraw:\n%s", rawStr)
	}
	if strings.Contains(rawStr, "Content-ID:") {
		t.Errorf("ordinary attachment must not emit Content-ID\nraw:\n%s", rawStr)
	}
	if !strings.Contains(rawStr, `Content-Disposition: attachment; filename="f.pdf"`) {
		t.Errorf("attachment disposition missing\nraw:\n%s", rawStr)
	}
}

// TestBuildMessage_ContentIDInjection rejects ids that could close the angle
// brackets early or smuggle MIME parameters, matching the guards already
// applied to filename and content_type (MAIL-3).
func TestBuildMessage_ContentIDInjection(t *testing.T) {
	for _, bad := range []string{
		"logo>\r\nX-Injected: yes",
		"logo>",
		"lo<go",
		`logo"`,
		"logo;name=x",
	} {
		msg := &Message{
			From:     Address{Email: "a@x"},
			To:       []Address{{Email: "b@y"}},
			Subject:  "t",
			HTMLBody: "<p>x</p>",
			Attachments: []Attachment{{
				Filename: "l.png", ContentType: "image/png", Content: pngPixel, ContentID: bad,
			}},
		}
		if _, err := buildMessage(msg, "id@h", "h"); err == nil {
			t.Errorf("content_id %q accepted, want rejection", bad)
		}
	}
}
