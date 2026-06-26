package mail

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// TestParseMultipart_PartCountBounded ensures an attacker-sent message with a
// huge number of parts cannot cause unbounded work/allocation: the parser stops
// after maxMIMEParts.
func TestParseMultipart_PartCountBounded(t *testing.T) {
	const boundary = "BOUND"
	var b strings.Builder
	b.WriteString("From: a@b.com\r\n")
	b.WriteString("To: c@d.com\r\n")
	b.WriteString("Subject: flood\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/mixed; boundary=" + boundary + "\r\n\r\n")
	for i := 0; i < maxMIMEParts+500; i++ {
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString(fmt.Sprintf("Content-Type: text/plain; name=\"a%d.txt\"\r\n", i))
		b.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"a%d.txt\"\r\n\r\n", i))
		b.WriteString("x\r\n")
	}
	b.WriteString("--" + boundary + "--\r\n")

	parsed, err := ParseRawMessage([]byte(b.String()))
	if err != nil {
		t.Fatalf("ParseRawMessage: %v", err)
	}
	if len(parsed.Attachments) > maxMIMEParts {
		t.Fatalf("attachments not bounded: got %d, want <= %d", len(parsed.Attachments), maxMIMEParts)
	}
}

// TestParseMultipart_DeepNestingTerminates ensures a deeply nested multipart
// message (a stack-exhaustion vector) terminates instead of recursing without
// bound. Success is simply that ParseRawMessage returns.
func TestParseMultipart_DeepNestingTerminates(t *testing.T) {
	// Build maxMIMEDepth+10 nested multipart/mixed levels, innermost a text part.
	levels := maxMIMEDepth + 10
	inner := "Content-Type: text/plain\r\n\r\nhello\r\n"
	body := inner
	for i := levels; i >= 1; i-- {
		boundary := fmt.Sprintf("B%d", i)
		var b strings.Builder
		b.WriteString("Content-Type: multipart/mixed; boundary=" + boundary + "\r\n\r\n")
		b.WriteString("--" + boundary + "\r\n")
		b.WriteString(body)
		b.WriteString("--" + boundary + "--\r\n")
		body = b.String()
	}
	raw := "From: a@b.com\r\nTo: c@d.com\r\nSubject: deep\r\nMIME-Version: 1.0\r\n" + body

	done := make(chan struct{})
	go func() {
		_, _ = ParseRawMessage([]byte(raw))
		close(done)
	}()
	select {
	case <-done:
		// terminated — good.
	case <-time.After(10 * time.Second):
		t.Fatal("ParseRawMessage did not terminate on deeply nested MIME")
	}
}
