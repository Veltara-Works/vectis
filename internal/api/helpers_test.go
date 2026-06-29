package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestParsePagination exercises the cursor/limit query-string parser, which is
// pure request-in / params-out logic with no DB dependency. It guards the
// default, clamping, and rejection paths that every paginated list endpoint
// relies on.
func TestParsePagination(t *testing.T) {
	validCursor := encodeCursor(time.Date(2026, 6, 16, 12, 0, 0, 0, time.UTC))

	tests := []struct {
		name       string
		query      string
		wantLimit  int
		wantCursor bool
		wantErr    bool
	}{
		{"defaults when empty", "", defaultPageLimit, false, false},
		{"explicit limit", "limit=10", 10, false, false},
		{"limit clamped to max", "limit=9999", maxPageLimit, false, false},
		{"limit at max", "limit=200", maxPageLimit, false, false},
		{"limit zero rejected", "limit=0", 0, false, true},
		{"limit negative rejected", "limit=-3", 0, false, true},
		{"limit non-integer rejected", "limit=abc", 0, false, true},
		{"valid cursor", "cursor=" + validCursor, defaultPageLimit, true, false},
		{"valid cursor with limit", "cursor=" + validCursor + "&limit=25", 25, true, false},
		{"bad base64 cursor", "cursor=!!!not-base64!!!", defaultPageLimit, false, true},
		{"non-timestamp cursor", "cursor=" + base64.URLEncoding.EncodeToString([]byte("not-a-time")), defaultPageLimit, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/items?"+tt.query, nil)
			got, err := parsePagination(r)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parsePagination(%q) = nil error, want error", tt.query)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePagination(%q) unexpected error: %v", tt.query, err)
			}
			if got.Limit != tt.wantLimit {
				t.Errorf("Limit = %d, want %d", got.Limit, tt.wantLimit)
			}
			if (got.Cursor != nil) != tt.wantCursor {
				t.Errorf("Cursor present = %v, want %v", got.Cursor != nil, tt.wantCursor)
			}
		})
	}
}

// TestEncodeCursorRoundTrip locks the opaque cursor contract: a time encoded by
// encodeCursor must decode back to the same instant through parsePagination,
// normalised to UTC. A drift here silently breaks keyset pagination continuity.
func TestEncodeCursorRoundTrip(t *testing.T) {
	// A non-UTC location to prove encodeCursor normalises to UTC.
	loc := time.FixedZone("AEST", 10*3600)
	orig := time.Date(2026, 6, 16, 21, 57, 3, 123456789, loc)

	enc := encodeCursor(orig)
	r := httptest.NewRequest(http.MethodGet, "/items?cursor="+enc, nil)
	got, err := parsePagination(r)
	if err != nil {
		t.Fatalf("round-trip parsePagination error: %v", err)
	}
	if got.Cursor == nil {
		t.Fatal("round-trip cursor is nil")
	}
	if !got.Cursor.Equal(orig) {
		t.Errorf("round-trip cursor = %v, want same instant as %v", got.Cursor, orig)
	}
	if !got.Cursor.Equal(orig.UTC()) || got.Cursor.Location() != time.UTC {
		t.Errorf("round-trip cursor not normalised to UTC: %v (loc %v)", got.Cursor, got.Cursor.Location())
	}
}

// TestMaskSubscriptionID guards the rule that a paying customer's full Stripe
// subscription id is never echoed back — only the last 6 chars behind a fixed
// prefix, with a uniform mask for anything too short to safely reveal a tail.
func TestMaskSubscriptionID(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty stays empty", "", ""},
		{"short fully masked", "sub_12", "sub_****"},
		{"exactly six fully masked", "abc123", "sub_****"},
		{"long reveals last six", "sub_1234567890ABCDEF", "sub_****ABCDEF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := maskSubscriptionID(tt.in)
			if got != tt.want {
				t.Errorf("maskSubscriptionID(%q) = %q, want %q", tt.in, got, tt.want)
			}
			// Invariant: the full id must never appear in the output.
			if len(tt.in) > 6 && strings.Contains(got, tt.in) {
				t.Errorf("maskSubscriptionID leaked full id %q in %q", tt.in, got)
			}
		})
	}
}

// TestFormatDuration covers the day/hour/minute boundary selection used by the
// system status endpoint's human-readable uptime string.
func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"sub-minute rounds to 0m", 30 * time.Second, "0m"},
		{"minutes only", 45 * time.Minute, "45m"},
		{"hours and minutes", 2*time.Hour + 15*time.Minute, "2h 15m"},
		{"exact hour", time.Hour, "1h 0m"},
		{"days and hours", 3*24*time.Hour + 5*time.Hour, "3d 5h"},
		{"days drop the minutes", 24*time.Hour + 90*time.Minute, "1d 1h"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatDuration(tt.d); got != tt.want {
				t.Errorf("formatDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

// TestValidateReturnURL pins the open-redirect guard. Because Stripe accepts any
// HTTPS URL we forward, any laxness here is exploitable as an open-redirect proxy
// through the ValidonX call chain — so the rejection cases matter as much as the
// accept cases.
func TestValidateReturnURL(t *testing.T) {
	const reqHost = "mail.example.com"
	tests := []struct {
		name    string
		raw     string
		host    string
		wantErr bool
	}{
		{"relative path allowed", "/account/billing", reqHost, false},
		{"same host https allowed", "https://mail.example.com/account/billing", reqHost, false},
		{"same host case-insensitive", "https://MAIL.Example.com/x", reqHost, false},
		{"request host with port ignored", "https://mail.example.com/x", "mail.example.com:8443", false},
		{"third-party host rejected", "https://evil.example.net/x", reqHost, true},
		{"non-http scheme rejected", "ftp://mail.example.com/x", reqHost, true},
		{"javascript scheme rejected", "javascript:alert(1)", reqHost, true},
		{"malformed url rejected", "https://mail.example.com/%zz", reqHost, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.Host = tt.host
			err := validateReturnURL(tt.raw, r)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateReturnURL(%q, host=%q) err = %v, wantErr = %v", tt.raw, tt.host, err, tt.wantErr)
			}
		})
	}
}

// TestDeriveOwnerName covers the keyless-checkout owner_name pre-fill derived
// from an email local-part (the endpoint 422s without a non-empty name).
func TestDeriveOwnerName(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"ian@example.com", "ian"},
		{"  spaced@example.com  ", "spaced"},
		{"no-at-symbol", ""},
		{"@example.com", ""},
		{"   @example.com", ""},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := deriveOwnerName(tt.in); got != tt.want {
				t.Errorf("deriveOwnerName(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestExtractDomainAndLocalPart covers the address-splitting helpers used by the
// send path, including the lowercasing and the malformed-address guards.
func TestExtractDomainAndLocalPart(t *testing.T) {
	tests := []struct {
		in        string
		wantLocal string
		wantDom   string
	}{
		{"User@Example.COM", "user", "example.com"},
		{"ian@vectismail.com", "ian", "vectismail.com"},
		// The two helpers validate independently: a present local part is
		// returned even when the domain half is empty, and vice versa.
		{"no-domain@", "no-domain", ""},
		{"@no-local.com", "", "no-local.com"},
		{"not-an-email", "", ""},
		{"a@b@c.com", "a", "b@c.com"}, // SplitN(_, 2) keeps the remainder as the domain
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := extractLocalPart(tt.in); got != tt.wantLocal {
				t.Errorf("extractLocalPart(%q) = %q, want %q", tt.in, got, tt.wantLocal)
			}
			if got := extractDomain(tt.in); got != tt.wantDom {
				t.Errorf("extractDomain(%q) = %q, want %q", tt.in, got, tt.wantDom)
			}
		})
	}
}

// TestIsValidSpamPattern covers scope-specific pattern validation for the spam
// allow/deny list endpoints.
func TestIsValidSpamPattern(t *testing.T) {
	tests := []struct {
		scope   string
		pattern string
		want    bool
	}{
		{"email", "spammer@bad.com", true},
		{"email", "bad.com", false},          // missing '@'
		{"email", "@bad.com", false},         // empty local part
		{"email", "x@", false},               // empty host
		{"email", "a@b@c.com", false},        // two '@'
		{"email", "ok@not_a_host", false},    // host fails domain regex
		{"domain", "bad.com", true},          //
		{"domain", "sub.bad.co.uk", true},    //
		{"domain", "spammer@bad.com", false}, // '@' not allowed in domain scope
		{"domain", "nodot", false},           //
		{"unknown", "anything", false},       // unknown scope is always invalid
	}
	for _, tt := range tests {
		t.Run(tt.scope+"/"+tt.pattern, func(t *testing.T) {
			if got := isValidSpamPattern(tt.scope, tt.pattern); got != tt.want {
				t.Errorf("isValidSpamPattern(%q, %q) = %v, want %v", tt.scope, tt.pattern, got, tt.want)
			}
		})
	}
}

// TestExtractSignedToken covers the cookie-first / Bearer-fallback token source
// precedence used by the session middleware.
func TestExtractSignedToken(t *testing.T) {
	t.Run("cookie wins over bearer", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: "vectis_session", Value: "cookie-tok"})
		r.Header.Set("Authorization", "Bearer header-tok")
		if got := extractSignedToken(r); got != "cookie-tok" {
			t.Errorf("got %q, want cookie-tok", got)
		}
	})
	t.Run("empty cookie falls back to bearer", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.AddCookie(&http.Cookie{Name: "vectis_session", Value: ""})
		r.Header.Set("Authorization", "Bearer header-tok")
		if got := extractSignedToken(r); got != "header-tok" {
			t.Errorf("got %q, want header-tok", got)
		}
	})
	t.Run("bearer only", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Bearer header-tok")
		if got := extractSignedToken(r); got != "header-tok" {
			t.Errorf("got %q, want header-tok", got)
		}
	})
	t.Run("non-bearer authorization ignored", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Authorization", "Basic abc123")
		if got := extractSignedToken(r); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
	t.Run("nothing present", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if got := extractSignedToken(r); got != "" {
			t.Errorf("got %q, want empty", got)
		}
	})
}

// TestRequireRole exercises the role-gate middleware end to end through an
// httptest recorder: the allowed role reaches the next handler, a disallowed
// role is short-circuited with a 403 and the FORBIDDEN error envelope.
func TestRequireRole(t *testing.T) {
	newReqWithRole := func(role string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		return r.WithContext(context.WithValue(r.Context(), ctxAdminRole, role))
	}

	t.Run("allowed role passes through", func(t *testing.T) {
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.WriteHeader(http.StatusOK)
		})
		rec := httptest.NewRecorder()
		requireRole("super_admin")(next).ServeHTTP(rec, newReqWithRole("super_admin"))
		if !called {
			t.Error("next handler was not called for allowed role")
		}
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	t.Run("disallowed role is forbidden", func(t *testing.T) {
		called := false
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
		rec := httptest.NewRecorder()
		requireRole("super_admin")(next).ServeHTTP(rec, newReqWithRole("viewer"))
		if called {
			t.Error("next handler should not be called for disallowed role")
		}
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
		var resp apiResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
			t.Fatalf("response is not valid JSON: %v", err)
		}
		if resp.Error == nil || resp.Error.Code != "FORBIDDEN" {
			t.Errorf("error envelope = %+v, want code FORBIDDEN", resp.Error)
		}
	})
}

// TestDecodeJSONLimit verifies that the body-size cap is enforced: a payload
// within the limit decodes, one over the limit fails rather than being read
// unbounded into memory.
func TestDecodeJSONLimit(t *testing.T) {
	type payload struct {
		Name string `json:"name"`
	}

	t.Run("within limit decodes", func(t *testing.T) {
		body := `{"name":"ian"}`
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		var p payload
		if err := decodeJSONLimit(r, &p, 1<<20); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Name != "ian" {
			t.Errorf("Name = %q, want ian", p.Name)
		}
	})

	t.Run("over limit rejected", func(t *testing.T) {
		body := `{"name":"` + strings.Repeat("x", 256) + `"}`
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body))
		var p payload
		if err := decodeJSONLimit(r, &p, 16); err == nil {
			t.Fatal("expected error for oversize body, got nil")
		}
	})
}

// TestValidDKIMSelector pins the charset guard that stops a PATCH-supplied DKIM
// selector from breaking out of the quoted `selector = "..."` field in the
// generated rspamd dkim_signing.conf (config injection). Only DNS-label
// characters are accepted; quotes, semicolons, braces, whitespace and newlines
// must be rejected.
func TestValidDKIMSelector(t *testing.T) {
	tests := []struct {
		sel  string
		want bool
	}{
		{"202603", true},           // date-based default
		{"default", true},          //
		{"key1.smtp", true},        // multi-label
		{"s-1", true},              // interior hyphen
		{"", false},                // empty
		{"-lead", false},           // leading hyphen
		{"trail-", false},          // trailing hyphen
		{".lead", false},           // leading dot
		{"trail.", false},          // trailing dot
		{"a..b", false},            // empty label
		{`sel"`, false},            // quote (breakout)
		{"a;b", false},             // semicolon
		{"a b", false},             // space
		{"a{b}", false},            // braces
		{"sel\ninjected", false},   // newline
		{"sel\"; } evil {", false}, // full injection payload
	}
	for _, tt := range tests {
		t.Run(tt.sel, func(t *testing.T) {
			if got := validDKIMSelectorRe.MatchString(tt.sel); got != tt.want {
				t.Errorf("validDKIMSelectorRe.MatchString(%q) = %v, want %v", tt.sel, got, tt.want)
			}
		})
	}
}

// TestUpdateDomainRejectsInjectionSelector verifies the PATCH handler rejects an
// injection-bearing dkim_selector with a 400 before it ever reaches the config
// engine. The rejection path returns prior to any DB access, so a bare Server
// suffices.
func TestUpdateDomainRejectsInjectionSelector(t *testing.T) {
	s := &Server{}
	body := `{"dkim_selector":"evil\"; } malicious {"}`
	r := httptest.NewRequest(http.MethodPatch, "/domains/d1", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.handleUpdateDomain(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	var resp apiResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != "INVALID_DKIM_SELECTOR" {
		t.Errorf("error envelope = %+v, want code INVALID_DKIM_SELECTOR", resp.Error)
	}
}

// TestSCIMCreateUserBodyCapped is the regression for the audit finding that SCIM
// user handlers decoded the request body with no size limit (memory exhaustion).
// An oversized body must be rejected at the decode boundary (400) rather than
// read unbounded into memory. The cap trips before any DB access.
func TestSCIMCreateUserBodyCapped(t *testing.T) {
	s := &Server{}
	huge := strings.Repeat("x", (1<<20)+1024) // > maxBodySize (1 MiB)
	body := `{"userName":"` + huge + `@example.com"}`
	r := httptest.NewRequest(http.MethodPost, "/scim/v2/Users", strings.NewReader(body))
	rec := httptest.NewRecorder()

	s.handleSCIMCreateUser(rec, r)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d (oversized SCIM body must be rejected)", rec.Code, http.StatusBadRequest)
	}
}
