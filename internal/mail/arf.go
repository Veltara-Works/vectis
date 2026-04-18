package mail

import (
	"bytes"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
)

// ARFReport represents a parsed RFC 5965 Abuse Reporting Format (feedback loop)
// complaint message. Only the fields we act on are populated; the full
// machine-readable section is retained in Raw for audit storage.
type ARFReport struct {
	// FeedbackType is the complaint category: abuse, fraud, virus, not-spam, other.
	FeedbackType string
	// ReportingMTA is the ISP or complaint processor reporting the complaint.
	ReportingMTA string
	// UserAgent is the software that generated the report.
	UserAgent string
	// SourceIP is the IP that sent the offending mail, if reported.
	SourceIP string
	// OriginalMailFrom is the envelope sender of the offending message.
	OriginalMailFrom string
	// OriginalRcptTo is the complainer's recipient address.
	OriginalRcptTo string
	// ReportedDomain is the domain the ISP holds responsible.
	ReportedDomain string
	// ArrivalDate is when the original message was received by the ISP.
	ArrivalDate string
	// OriginalMessageID is the Message-ID of the offending message, extracted
	// from the attached rfc822 / rfc822-headers part (if present).
	OriginalMessageID string
	// OriginalFrom is the From: header of the offending message.
	OriginalFrom string
	// Raw holds all machine-readable field/value pairs for storage as JSON.
	Raw map[string]string
}

// IsARFReport returns true if the given top-level Content-Type indicates an
// RFC 5965 feedback report. Accepts either raw or lowercased input.
func IsARFReport(contentType string) bool {
	if contentType == "" {
		return false
	}
	mediaType, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}
	if !strings.EqualFold(mediaType, "multipart/report") {
		return false
	}
	return strings.EqualFold(params["report-type"], "feedback-report")
}

// ParseARF parses a raw RFC 5322 message that carries an ARF feedback report.
// Returns an error only when the outer structure is unparseable; missing
// optional fields populate as empty strings.
func ParseARF(raw []byte) (*ARFReport, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parse arf outer message: %w", err)
	}

	contentType := msg.Header.Get("Content-Type")
	if !IsARFReport(contentType) {
		return nil, fmt.Errorf("not an ARF feedback-report (content-type=%q)", contentType)
	}

	_, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return nil, fmt.Errorf("parse arf content-type: %w", err)
	}
	boundary := params["boundary"]
	if boundary == "" {
		return nil, fmt.Errorf("arf multipart missing boundary")
	}

	report := &ARFReport{Raw: make(map[string]string)}

	reader := multipart.NewReader(msg.Body, boundary)
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("arf next part: %w", err)
		}
		partCT := part.Header.Get("Content-Type")
		mediaType, _, _ := mime.ParseMediaType(partCT)

		switch {
		case strings.EqualFold(mediaType, "message/feedback-report"):
			body, _ := io.ReadAll(io.LimitReader(part, 64<<10))
			parseFeedbackReportFields(body, report)

		case strings.EqualFold(mediaType, "message/rfc822"),
			strings.EqualFold(mediaType, "text/rfc822-headers"):
			body, _ := io.ReadAll(io.LimitReader(part, 256<<10))
			extractOriginalHeaders(body, report)
		}
	}

	// If the feedback-report part didn't specify ReportedDomain, derive it
	// from OriginalMailFrom. ISPs vary.
	if report.ReportedDomain == "" && report.OriginalMailFrom != "" {
		if at := strings.LastIndex(report.OriginalMailFrom, "@"); at > 0 {
			d := strings.TrimRight(report.OriginalMailFrom[at+1:], ">")
			report.ReportedDomain = strings.ToLower(d)
		}
	}

	return report, nil
}

// parseFeedbackReportFields extracts RFC 5965 machine-readable fields.
func parseFeedbackReportFields(body []byte, report *ARFReport) {
	// The feedback-report part is itself a set of header-like key/value lines.
	lines := bytes.Split(body, []byte("\n"))
	for _, line := range lines {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		colon := bytes.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(string(line[:colon])))
		val := strings.TrimSpace(string(line[colon+1:]))
		report.Raw[key] = val

		switch key {
		case "feedback-type":
			report.FeedbackType = strings.ToLower(val)
		case "user-agent":
			report.UserAgent = val
		case "reporting-mta":
			// Format: "dns; hostname"
			if semi := strings.Index(val, ";"); semi >= 0 {
				report.ReportingMTA = strings.TrimSpace(val[semi+1:])
			} else {
				report.ReportingMTA = val
			}
		case "source-ip":
			report.SourceIP = val
		case "original-mail-from":
			report.OriginalMailFrom = strings.Trim(val, "<>")
		case "original-rcpt-to":
			report.OriginalRcptTo = strings.Trim(val, "<>")
		case "reported-domain":
			report.ReportedDomain = strings.ToLower(strings.TrimSpace(val))
		case "arrival-date", "received-date":
			report.ArrivalDate = val
		}
	}
}

// extractOriginalHeaders pulls Message-ID and From out of the attached
// original message (or headers-only part).
func extractOriginalHeaders(body []byte, report *ARFReport) {
	orig, err := mail.ReadMessage(bytes.NewReader(body))
	if err != nil {
		// May be headers-only without the blank separator — try adding one.
		alt, altErr := mail.ReadMessage(bytes.NewReader(append(bytes.TrimRight(body, "\r\n"), []byte("\r\n\r\n")...)))
		if altErr != nil {
			return
		}
		orig = alt
	}
	if id := orig.Header.Get("Message-ID"); id != "" {
		report.OriginalMessageID = strings.Trim(id, "<>")
	} else if id := orig.Header.Get("Message-Id"); id != "" {
		report.OriginalMessageID = strings.Trim(id, "<>")
	}
	if from := orig.Header.Get("From"); from != "" {
		report.OriginalFrom = from
	}
	if report.OriginalMailFrom == "" {
		if rp := orig.Header.Get("Return-Path"); rp != "" {
			report.OriginalMailFrom = strings.Trim(rp, "<>")
		}
	}
}

// ComplaintTypeForDB maps an ARF feedback-type to the narrow set the
// fbl_reports.complaint_type column accepts (abuse/fraud/virus/other).
// "not-spam" is kept as "other" — it's a user correction, not a complaint.
func ComplaintTypeForDB(feedbackType string) string {
	switch strings.ToLower(strings.TrimSpace(feedbackType)) {
	case "abuse":
		return "abuse"
	case "fraud":
		return "fraud"
	case "virus":
		return "virus"
	default:
		return "other"
	}
}
