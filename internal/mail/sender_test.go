package mail

import (
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
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
