package cli

import (
	"strings"
	"testing"
)

func TestIsMalformedEmail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		// The rc25 walkthrough bug — user typed `vectis preflight` as
		// hostname, script derived `admin@vectis preflight` as email.
		// This is the exact class this guardrail exists to stop.
		{"space in domain (rc25 walkthrough bug)", "admin@vectis preflight", true},
		{"leading whitespace", " admin@foo.com", false}, // trimmed before check
		{"embedded tab", "admin@\tfoo.com", true},
		{"missing @", "adminfoo.com", true},
		{"empty local", "@foo.com", true},
		{"empty domain", "admin@", true},
		{"no dot in domain", "admin@localhost", true},
		{"valid FQDN domain", "admin@mail.example.com", false},
		{"valid simple FQDN", "admin@example.com", false},
		{"empty string", "", false}, // empty handled separately for clearer error
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isMalformedEmail(tc.in)
			if got != tc.want {
				t.Errorf("isMalformedEmail(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestCondenseLine(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"trim whitespace", "  hello  ", "hello"},
		{"collapse newlines", "line1\nline2\nline3", "line1 line2 line3"},
		{"collapse carriage returns", "line1\rline2", "line1 line2"},
		{"collapse multiple spaces", "a    b  c", "a b c"},
		{"truncate at 200 with ellipsis", strings.Repeat("x", 300), strings.Repeat("x", 197) + "..."},
		{"exactly 200 stays", strings.Repeat("y", 200), strings.Repeat("y", 200)},
		{"201 truncates", strings.Repeat("z", 201), strings.Repeat("z", 197) + "..."},
		{"empty", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := condenseLine(tc.in)
			if got != tc.want {
				t.Errorf("condenseLine(%q) len=%d, want len=%d\ngot  %q\nwant %q", tc.in, len(got), len(tc.want), got, tc.want)
			}
		})
	}
}

func TestExtractACMEErrorFromLogs(t *testing.T) {
	// Real-world-shaped log line from the 2026-04-23 rc28 walkthrough
	// when Let's Encrypt rate-limited our hostname. This is the exact
	// scenario rc31 is designed to surface clearly to operators.
	rateLimitLog := `{"level":"info","time":"2026-04-23T07:30:03Z","message":"Starting provider *acme.Provider"}
{"level":"info","providerName":"letsencrypt.acme","time":"2026-04-23T07:30:07Z","message":"Register..."}
{"level":"error","providerName":"letsencrypt.acme","error":"unable to generate a certificate for the domains [mail.sysadmin1001.com]: acme: error: 429 :: POST :: https://acme-v02.api.letsencrypt.org/acme/new-order :: urn:ietf:params:acme:error:rateLimited :: too many certificates (5) already issued for this exact set of identifiers in the last 168h0m0s, retry after 2026-04-23 21:09:53 UTC","domains":["mail.sysadmin1001.com"],"time":"2026-04-23T07:30:09Z","message":"Unable to obtain ACME certificate for domains"}
{"level":"info","time":"2026-04-23T07:30:14Z","message":"I have to go..."}`

	got := extractACMEErrorFromLogs(rateLimitLog)
	if got == "" {
		t.Fatal("expected extraction, got empty string")
	}
	if !strings.Contains(got, "rateLimited") {
		t.Errorf("extraction should include rateLimited keyword; got %q", got)
	}
	if !strings.Contains(got, "429") {
		t.Errorf("extraction should include the 429 status; got %q", got)
	}
	// Should pick the `error` field, not the shorter `message` field.
	if strings.Contains(got, "Unable to obtain ACME") && !strings.Contains(got, "too many certificates") {
		t.Errorf("prefer error field over message; got %q", got)
	}
}

func TestExtractACMEErrorFromLogs_IgnoresInfoLevelLines(t *testing.T) {
	logs := `{"level":"info","time":"2026-04-23T07:30:03Z","message":"Starting provider"}
{"level":"info","time":"2026-04-23T07:30:07Z","message":"acme Register..."}`
	got := extractACMEErrorFromLogs(logs)
	if got != "" {
		t.Errorf("info-level lines should not produce extraction; got %q", got)
	}
}

func TestExtractACMEErrorFromLogs_IgnoresUnrelatedErrors(t *testing.T) {
	// An error that's not about ACME/rate-limiting shouldn't be surfaced —
	// the banner is specifically about TLS issuance, so showing an
	// unrelated "postfix connection reset" would confuse operators.
	logs := `{"level":"error","time":"2026-04-23T07:30:03Z","message":"postfix connection reset by peer","error":"read: connection reset by peer"}`
	got := extractACMEErrorFromLogs(logs)
	if got != "" {
		t.Errorf("unrelated errors should not surface; got %q", got)
	}
}

func TestExtractACMEErrorFromLogs_ReturnsMostRecent(t *testing.T) {
	// If there are multiple ACME errors across the scrape window (e.g.
	// first attempt + retry both failed), we want the LAST one since that
	// reflects the current state.
	logs := `{"level":"error","time":"2026-04-23T07:00:00Z","message":"Unable to obtain ACME certificate","error":"acme: error old"}
{"level":"error","time":"2026-04-23T07:10:00Z","message":"Unable to obtain ACME certificate","error":"acme: error newer"}`
	got := extractACMEErrorFromLogs(logs)
	if got != "acme: error newer" {
		t.Errorf("should return most recent; got %q", got)
	}
}

func TestExtractACMEErrorFromLogs_FallsBackToPlainText(t *testing.T) {
	// Not all traefik output is JSON (container startup banner, some
	// panics). If we hit a matching plain-text line it should still
	// surface.
	logs := `ERROR: acme challenge failed: connection refused on :80`
	got := extractACMEErrorFromLogs(logs)
	if got == "" {
		t.Errorf("plain-text ACME error should surface; got empty string")
	}
	if !strings.Contains(got, "acme challenge failed") {
		t.Errorf("got unexpected content: %q", got)
	}
}

func TestIsPlaceholderEmail(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want bool
	}{
		{"shipped default", "admin@example.com", true},
		{"historical placeholder", "my@example.com", true},
		{"uppercase example domain", "ADMIN@EXAMPLE.COM", true},
		{"leading whitespace", "  admin@example.com  ", true},
		{"subdomain of example.com is not example.com proper", "admin@mail.example.com", false},
		{"real address", "ops@vectismail.com", false},
		{"empty string", "", false}, // empty is handled separately for clearer error
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isPlaceholderEmail(tc.in)
			if got != tc.want {
				t.Errorf("isPlaceholderEmail(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

func TestPickAPIImage(t *testing.T) {
	const compose = `services:
  traefik:
    image: traefik:v3.3
  api:
    image: ghcr.io/veltara-works/vectis-api:v0.1.28
    container_name: vectis-api
  orchestrator:
    image: ghcr.io/veltara-works/vectis-orchestrator:v0.1.28
  postfix:
    image: ghcr.io/veltara-works/vectis-postfix:v0.1.28
`
	got := pickAPIImage(compose)
	want := "ghcr.io/veltara-works/vectis-api:v0.1.28"
	if got != want {
		t.Errorf("pickAPIImage() = %q, want %q", got, want)
	}

	// Must not match the orchestrator/postfix lines if api is absent.
	const noAPI = `services:
  orchestrator:
    image: ghcr.io/veltara-works/vectis-orchestrator:v0.1.28
`
	if got := pickAPIImage(noAPI); got != "" {
		t.Errorf("pickAPIImage(noAPI) = %q, want empty", got)
	}
}

func TestDockerRunAPI(t *testing.T) {
	got := dockerRunAPI("ghcr.io/veltara-works/vectis-api:v0.1.28", "vectis", "migrate", "up")
	want := []string{
		"docker", "run", "--rm",
		"--network", "vectis_vectis-data",
		"-v", "/etc/vectis:/etc/vectis:ro",
		"--entrypoint", "vectis",
		"ghcr.io/veltara-works/vectis-api:v0.1.28",
		"migrate", "up",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("dockerRunAPI()\n got: %v\nwant: %v", got, want)
	}

	// It must never shell out to `docker compose run` (the detach footgun).
	if strings.Contains(strings.Join(got, " "), "compose run") {
		t.Error("dockerRunAPI() must not use `docker compose run`")
	}
}
