package mail

import (
	"strings"
	"testing"
)

// Example ARF message adapted from RFC 5965 appendix with CRLFs.
const sampleARF = "From: <complaints@isp.example>\r\n" +
	"To: <abuse@mail.example.com>\r\n" +
	"Subject: FW: Earn money\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: multipart/report; report-type=feedback-report; boundary=\"b1\"\r\n" +
	"\r\n" +
	"--b1\r\n" +
	"Content-Type: text/plain; charset=\"us-ascii\"\r\n" +
	"\r\n" +
	"This is an email abuse report for an email message received from IP\r\n" +
	"203.0.113.4 on Thu, 8 Mar 2007 17:40:36 -0500.\r\n" +
	"\r\n" +
	"--b1\r\n" +
	"Content-Type: message/feedback-report\r\n" +
	"\r\n" +
	"Feedback-Type: abuse\r\n" +
	"User-Agent: SomeGenerator/1.0\r\n" +
	"Version: 1\r\n" +
	"Original-Mail-From: <sender@mail.example.com>\r\n" +
	"Original-Rcpt-To: <user@isp.example>\r\n" +
	"Arrival-Date: Thu, 8 Mar 2007 17:40:36 -0500\r\n" +
	"Reporting-MTA: dns; mail.isp.example\r\n" +
	"Source-IP: 203.0.113.4\r\n" +
	"Reported-Domain: mail.example.com\r\n" +
	"\r\n" +
	"--b1\r\n" +
	"Content-Type: message/rfc822\r\n" +
	"\r\n" +
	"From: <sender@mail.example.com>\r\n" +
	"To: <user@isp.example>\r\n" +
	"Subject: Earn money\r\n" +
	"Message-ID: <abc-123@mail.example.com>\r\n" +
	"\r\n" +
	"Spam spam spam\r\n" +
	"--b1--\r\n"

func TestIsARFReport(t *testing.T) {
	if !IsARFReport(`multipart/report; report-type=feedback-report; boundary=b1`) {
		t.Fatalf("expected true for feedback-report")
	}
	if IsARFReport(`multipart/mixed; boundary=x`) {
		t.Fatalf("expected false for multipart/mixed")
	}
	if IsARFReport(`multipart/report; report-type=delivery-status; boundary=b1`) {
		t.Fatalf("expected false for DSN (delivery-status)")
	}
	if IsARFReport("") {
		t.Fatalf("empty should be false")
	}
}

func TestParseARF_HappyPath(t *testing.T) {
	r, err := ParseARF([]byte(sampleARF))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.FeedbackType != "abuse" {
		t.Errorf("feedback-type: got %q, want abuse", r.FeedbackType)
	}
	if r.OriginalMailFrom != "sender@mail.example.com" {
		t.Errorf("original-mail-from: got %q", r.OriginalMailFrom)
	}
	if r.OriginalRcptTo != "user@isp.example" {
		t.Errorf("original-rcpt-to: got %q", r.OriginalRcptTo)
	}
	if r.ReportedDomain != "mail.example.com" {
		t.Errorf("reported-domain: got %q", r.ReportedDomain)
	}
	if r.SourceIP != "203.0.113.4" {
		t.Errorf("source-ip: got %q", r.SourceIP)
	}
	if r.UserAgent != "SomeGenerator/1.0" {
		t.Errorf("user-agent: got %q", r.UserAgent)
	}
	if r.ReportingMTA != "mail.isp.example" {
		t.Errorf("reporting-mta: got %q", r.ReportingMTA)
	}
	if r.OriginalMessageID != "abc-123@mail.example.com" {
		t.Errorf("original-message-id: got %q", r.OriginalMessageID)
	}
	if !strings.Contains(r.OriginalFrom, "sender@mail.example.com") {
		t.Errorf("original-from: got %q", r.OriginalFrom)
	}
	if r.Raw["feedback-type"] != "abuse" {
		t.Errorf("raw map should preserve feedback-type")
	}
}

func TestParseARF_RejectsNonARF(t *testing.T) {
	plain := "From: a@b\r\nTo: c@d\r\nContent-Type: text/plain\r\n\r\nhello"
	if _, err := ParseARF([]byte(plain)); err == nil {
		t.Fatalf("expected error for non-ARF message")
	}
}

// TestParseARF_LargePartStillAdvances proves the reader advances past a part
// larger than the per-part LimitReader cap: mime/multipart's NextPart() closes
// (drains) the previous part, so the rfc822 part AFTER an oversized
// feedback-report part is still reached and parsed. Guards against a regression
// if the loop were ever changed to rely on full part consumption.
func TestParseARF_LargePartStillAdvances(t *testing.T) {
	pad := strings.Repeat("x", 100<<10) // 100 KB, well past the 64 KB feedback-report cap
	msg := "From: <c@isp.example>\r\n" +
		"To: <abuse@m.example>\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/report; report-type=feedback-report; boundary=\"b1\"\r\n\r\n" +
		"--b1\r\nContent-Type: message/feedback-report\r\n\r\n" +
		"Feedback-Type: abuse\r\nVersion: 1\r\nOriginal-Mail-From: <s@m.example>\r\n" +
		"X-Pad: " + pad + "\r\n" +
		"\r\n--b1\r\nContent-Type: message/rfc822\r\n\r\n" +
		"Message-ID: <big-123@m.example>\r\n\r\nbody\r\n" +
		"--b1--\r\n"
	r, err := ParseARF([]byte(msg))
	if err != nil {
		t.Fatalf("parse failed on an oversized part (NextPart should auto-drain + advance): %v", err)
	}
	if r.FeedbackType != "abuse" {
		t.Errorf("feedback-type (pre-cap field) not parsed: %q", r.FeedbackType)
	}
	if r.OriginalMessageID != "big-123@m.example" {
		t.Errorf("rfc822 part after the oversized part was not reached: msgid=%q", r.OriginalMessageID)
	}
}

// TestParseARF_RejectsTooManyParts is the #173 DoS guard: a feedback report with
// a huge number of MIME parts must be rejected rather than spinning the
// NextPart() loop unbounded.
func TestParseARF_RejectsTooManyParts(t *testing.T) {
	var b strings.Builder
	b.WriteString("From: <complaints@isp.example>\r\n")
	b.WriteString("To: <abuse@mail.example.com>\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/report; report-type=feedback-report; boundary=\"b1\"\r\n\r\n")
	for i := 0; i < maxARFParts+5; i++ {
		b.WriteString("--b1\r\nContent-Type: text/plain\r\n\r\njunk\r\n")
	}
	b.WriteString("--b1--\r\n")
	if _, err := ParseARF([]byte(b.String())); err == nil {
		t.Fatalf("expected error for an ARF report exceeding %d parts", maxARFParts)
	}
}

func TestParseARF_DomainDerivedFromMailFrom(t *testing.T) {
	// Strip Reported-Domain from sample to force derivation fallback.
	stripped := strings.Replace(sampleARF,
		"Reported-Domain: mail.example.com\r\n", "", 1)
	r, err := ParseARF([]byte(stripped))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.ReportedDomain != "mail.example.com" {
		t.Errorf("expected domain derived from mail-from, got %q", r.ReportedDomain)
	}
}

func TestComplaintTypeForDB(t *testing.T) {
	cases := map[string]string{
		"abuse":    "abuse",
		"Abuse":    "abuse",
		"fraud":    "fraud",
		"virus":    "virus",
		"not-spam": "other",
		"other":    "other",
		"":         "other",
	}
	for in, want := range cases {
		if got := ComplaintTypeForDB(in); got != want {
			t.Errorf("ComplaintTypeForDB(%q): got %q, want %q", in, got, want)
		}
	}
}
