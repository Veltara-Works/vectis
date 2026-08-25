package engine

import (
	"strings"
	"testing"
)

// renderPostfixFiles renders the templates and returns the files this feature
// touches, so each test can assert on them without repeating the plumbing.
func renderPostfixFiles(t *testing.T, mutate func(*TemplateData)) (master, checks, compose string) {
	t.Helper()
	data := testData()
	if mutate != nil {
		mutate(data)
	}
	files, err := Generate(data)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	for _, f := range files {
		switch f.RelPath {
		case "postfix/master.cf":
			master = string(f.Content)
		case "postfix/submission_header_checks":
			checks = string(f.Content)
		case "docker-compose.yml":
			compose = string(f.Content)
		}
	}
	if master == "" || checks == "" {
		t.Fatal("expected postfix/master.cf and postfix/submission_header_checks to be rendered")
	}
	return master, checks, compose
}

// Default ON: an install with no strip_submission_client_headers key (nil
// pointer) must get the sanitisation, so existing installs stop leaking the
// tenant's client IP to recipients on upgrade.
func TestSubmissionHeaderStrip_DefaultOn(t *testing.T) {
	master, checks, compose := renderPostfixFiles(t, nil)

	if !strings.Contains(master, "submission-cleanup unix") {
		t.Error("master.cf is missing the submission-cleanup service")
	}
	if got := strings.Count(master, "-o cleanup_service_name=submission-cleanup"); got != 2 {
		t.Errorf("cleanup_service_name wired to %d listeners, want 2 (submission AND smtps)", got)
	}
	if !strings.Contains(master, "-o header_checks=regexp:/etc/postfix/submission_header_checks") {
		t.Error("submission-cleanup does not apply the header_checks map")
	}
	if !strings.Contains(checks, "REPLACE Received: from [redacted]") {
		t.Error("sanitising REPLACE rule missing")
	}
	if !strings.Contains(checks, "/^X-Originating-IP:/ IGNORE") {
		t.Error("X-Originating-IP rule missing")
	}
	if compose != "" && !strings.Contains(compose, "/etc/postfix/submission_header_checks:ro") {
		t.Error("header_checks file is not mounted into the postfix container")
	}
}

// The map MUST be regexp:, never pcre: — the vectis-postfix image does not ship
// postfix-pcre, so a pcre map fails to load and takes submission down with it.
func TestSubmissionHeaderStrip_UsesRegexpNotPcre(t *testing.T) {
	master, _, _ := renderPostfixFiles(t, nil)
	if strings.Contains(master, "pcre:/etc/postfix/submission_header_checks") {
		t.Fatal("header_checks uses pcre: — the postfix image has no postfix-pcre; must be regexp:")
	}
}

// Inbound :25 must keep the DEFAULT cleanup service. Applying these rules there
// would strip inbound Received chains and break hop-count loop detection.
func TestSubmissionHeaderStrip_InboundPort25Untouched(t *testing.T) {
	master, _, _ := renderPostfixFiles(t, nil)
	lines := strings.Split(master, "\n")
	for i, l := range lines {
		if !strings.HasPrefix(l, "smtp      inet") {
			continue
		}
		for _, o := range lines[i+1:] {
			if !strings.HasPrefix(o, "  -o ") {
				break
			}
			if strings.Contains(o, "cleanup_service_name") {
				t.Fatal("inbound smtp (:25) was wired to submission-cleanup — would break inbound trace + loop detection")
			}
		}
	}
}

// Fail closed: the catch-all IGNORE must come AFTER the REPLACE, because
// Postfix stops at the first matching rule. Reversed, nothing would ever be
// sanitised; missing, an unmatched Received would reach the recipient intact.
func TestSubmissionHeaderStrip_FailsClosed(t *testing.T) {
	_, checks, _ := renderPostfixFiles(t, nil)
	replaceAt := strings.Index(checks, "REPLACE Received: from [redacted]")
	ignoreAt := strings.Index(checks, "/^Received:/ IGNORE")
	if replaceAt < 0 || ignoreAt < 0 {
		t.Fatal("expected both a REPLACE and a catch-all IGNORE for Received")
	}
	if ignoreAt < replaceAt {
		t.Fatal("catch-all IGNORE precedes the REPLACE — Postfix stops at the first match, so nothing would ever be sanitised")
	}
}

// The REPLACE must keep the "by <us> (Postfix) with <proto>" hop, so the
// message still carries the trace information RFC 5321 s4.4 requires. A rule
// that deleted the whole header would be simpler but is a spec deviation for
// no privacy gain — our hostname is already public via MX/SPF/DKIM.
func TestSubmissionHeaderStrip_PreservesTraceHop(t *testing.T) {
	_, checks, _ := renderPostfixFiles(t, nil)
	if !strings.Contains(checks, "REPLACE Received: from [redacted] by $1 (Postfix) with $2") {
		t.Error("REPLACE does not preserve the 'by <host> (Postfix) with <proto>' trace hop")
	}
}

// Opt-out must remove the wiring entirely, not just the rules.
func TestSubmissionHeaderStrip_Disabled(t *testing.T) {
	off := false
	master, checks, compose := renderPostfixFiles(t, func(d *TemplateData) {
		d.Postfix.StripSubmissionClientHeaders = &off
	})
	if strings.Contains(master, "submission-cleanup") {
		t.Error("submission-cleanup still wired while disabled")
	}
	if strings.Contains(checks, "IGNORE") || strings.Contains(checks, "REPLACE") {
		t.Error("rules still active while disabled")
	}
	// Still mounted, so toggling never needs a compose/mount change.
	if compose != "" && !strings.Contains(compose, "/etc/postfix/submission_header_checks:ro") {
		t.Error("file should stay mounted even when disabled, to avoid a mount change on toggle")
	}
}

// Operator-configured extras are opt-in and emitted verbatim as IGNORE rules.
func TestSubmissionHeaderStrip_ExtraHeaders(t *testing.T) {
	_, base, _ := renderPostfixFiles(t, nil)
	if strings.Contains(base, "X-Mailer") || strings.Contains(base, "User-Agent") {
		t.Error("X-Mailer/User-Agent stripped by default — they are author content and must be opt-in")
	}
	_, checks, _ := renderPostfixFiles(t, func(d *TemplateData) {
		d.Postfix.StripSubmissionExtraHeaders = []string{"X-Mailer", "User-Agent"}
	})
	for _, h := range []string{"/^X-Mailer:/ IGNORE", "/^User-Agent:/ IGNORE"} {
		if !strings.Contains(checks, h) {
			t.Errorf("missing configured rule %q", h)
		}
	}
}
