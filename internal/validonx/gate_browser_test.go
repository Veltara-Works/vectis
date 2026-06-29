package validonx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Veltara-Works/vectis/internal/config"
)

// ---------------------------------------------------------------------------
// wantsJSON — pure helper, exhaustive table test
// ---------------------------------------------------------------------------

func TestWantsJSON(t *testing.T) {
	tests := []struct {
		name   string
		accept string
		want   bool
	}{
		{"empty header defaults to HTML", "", false},
		{"missing header defaults to HTML", "<unset>", false},
		{"browser default with q-values", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", false},
		{"explicit text/html only", "text/html", false},
		{"explicit application/json only", "application/json", true},
		{"json then html → html wins", "application/json, text/html", false},
		{"html then json → html wins", "text/html, application/json", false},
		{"wildcard alone defaults to HTML", "*/*", false},
		{"unknown content type defaults to HTML", "application/octet-stream", false},
		{"case-insensitive match: APPLICATION/JSON", "APPLICATION/JSON", true},
		{"case-insensitive match: TEXT/HTML wins", "TEXT/HTML, application/json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.accept != "<unset>" {
				req.Header.Set("Accept", tt.accept)
			}
			if got := wantsJSON(req); got != tt.want {
				t.Errorf("wantsJSON(%q) = %v, want %v", tt.accept, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HasFeature — public surface used by handleOIDCProviders
// ---------------------------------------------------------------------------

func TestHasFeature_Unconfigured(t *testing.T) {
	gate := NewFeatureGateService(nil, nil, testLogger())

	// Unconfigured = Free tier (since v0.1.6). Free-tier features remain
	// available; Pro/Enterprise features must report unavailable so the
	// OIDC providers list is suppressed and other handlers behave as if
	// the customer holds no Pro entitlement. See
	// feedback_featuregate_unconfigured_bypass.md.
	if !gate.HasFeature(context.Background(), FeatureBasicMail) {
		t.Error("unconfigured gate must report basic_mail as available")
	}
	if gate.HasFeature(context.Background(), FeatureOIDCSSO) {
		t.Error("unconfigured gate must NOT report oidc_sso as available — Free tier has no Pro features")
	}
	if gate.HasFeature(context.Background(), FeatureAnalytics) {
		t.Error("unconfigured gate must NOT report analytics as available — Free tier has no Pro features")
	}
	if gate.HasFeature(context.Background(), FeatureSLA) {
		t.Error("unconfigured gate must NOT report sla as available — Free tier has no Enterprise features")
	}
}

func TestHasFeature_FreeTierFeature_Configured(t *testing.T) {
	// A configured client + nil cache means feature lookups deny by default,
	// EXCEPT for free-tier features which short-circuit. This pins that
	// short-circuit so future refactors don't regress basic_mail to "denied
	// when license cache is empty".
	c := NewClient(&config.ValidonXSecrets{
		BaseURL: "http://localhost:0", ServiceKey: "k",
	}, testLogger())
	gate := NewFeatureGateService(c, nil, testLogger())

	if !gate.HasFeature(context.Background(), FeatureBasicMail) {
		t.Error("basic_mail must remain available even when cache is unpopulated")
	}
}

// ---------------------------------------------------------------------------
// FeatureGateBrowser — content-negotiated request-layer gate
// ---------------------------------------------------------------------------

// allowingHandler counts invocations so deny tests can assert next.ServeHTTP
// was NOT called.
type allowingHandler struct{ called int }

func (h *allowingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.called++
	w.WriteHeader(http.StatusOK)
}

// TestFeatureGateBrowser_Unconfigured_NonFree_Denies pins the v0.1.6 fix:
// an unconfigured install is Free tier, and Pro/Enterprise features must
// render the upgrade page (or 403 JSON) rather than passing through.
// See feedback_featuregate_unconfigured_bypass.md.
func TestFeatureGateBrowser_Unconfigured_NonFree_Denies(t *testing.T) {
	gate := NewFeatureGateService(nil, nil, testLogger())

	next := &allowingHandler{}
	mw := gate.FeatureGateBrowser(FeatureOIDCSSO, "OIDC single sign-on", "")(next)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login/google", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if next.called != 0 {
		t.Errorf("unconfigured gate must NOT pass through Pro features; next called %d times", next.called)
	}
	if rec.Code != http.StatusPaymentRequired {
		t.Errorf("status = %d, want 402 (HTML upgrade page)", rec.Code)
	}
}

// TestFeatureGateBrowser_Unconfigured_NonFree_DeniesJSON checks the JSON
// content-negotiation branch of the same fix: API clients that explicitly
// ask for JSON get the 403 envelope rather than HTML.
func TestFeatureGateBrowser_Unconfigured_NonFree_DeniesJSON(t *testing.T) {
	gate := NewFeatureGateService(nil, nil, testLogger())

	next := &allowingHandler{}
	mw := gate.FeatureGateBrowser(FeatureOIDCSSO, "OIDC single sign-on", "")(next)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login/google", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if next.called != 0 {
		t.Errorf("unconfigured gate must NOT pass through Pro features; next called %d times", next.called)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403 (JSON envelope)", rec.Code)
	}
}

// TestFeatureGateBrowser_Unconfigured_FreeTier_Allows pins the partial-allow
// path: free-tier features (basic_mail) still pass on an unconfigured gate.
func TestFeatureGateBrowser_Unconfigured_FreeTier_Allows(t *testing.T) {
	gate := NewFeatureGateService(nil, nil, testLogger())

	next := &allowingHandler{}
	mw := gate.FeatureGateBrowser(FeatureBasicMail, "basic mail", "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if next.called != 1 {
		t.Errorf("free-tier feature must pass through on unconfigured gate; next called %d times", next.called)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

func TestFeatureGateBrowser_FreeTierFeature_Allows(t *testing.T) {
	c := NewClient(&config.ValidonXSecrets{
		BaseURL: "http://localhost:0", ServiceKey: "k",
	}, testLogger())
	gate := NewFeatureGateService(c, nil, testLogger())

	next := &allowingHandler{}
	mw := gate.FeatureGateBrowser(FeatureBasicMail, "basic mail", "")(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if next.called != 1 {
		t.Errorf("free-tier feature must pass through even on configured gate; next called %d times", next.called)
	}
}

// configuredDenyingGate returns a gate whose Client is configured (so the
// free-tier passthrough doesn't fire) but whose cache is nil, which causes
// checkFeatureAccess to return (false, nil) — a clean deny-with-no-error
// path that exercises the negotiation branch without needing a fake
// ValidonX server or a real Postgres.
func configuredDenyingGate(t *testing.T) *FeatureGateService {
	t.Helper()
	c := NewClient(&config.ValidonXSecrets{
		BaseURL: "http://localhost:0", ServiceKey: "k",
	}, testLogger())
	if !c.Configured() {
		t.Fatal("test setup: client should be Configured()")
	}
	return NewFeatureGateService(c, nil, testLogger())
}

func TestFeatureGateBrowser_Deny_HTMLAccept_RendersUpgradePage(t *testing.T) {
	gate := configuredDenyingGate(t)
	next := &allowingHandler{}
	mw := gate.FeatureGateBrowser(FeatureOIDCSSO,
		"OIDC single sign-on", "https://vectismail.com/pricing")(next)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login/google", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if next.called != 0 {
		t.Errorf("deny path must NOT invoke next; called %d times", next.called)
	}
	if rec.Code != http.StatusPaymentRequired {
		t.Errorf("status = %d, want 402", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"OIDC single sign-on",            // featureLabel must appear
		"https://vectismail.com/pricing", // upgrade link must appear
		"<!doctype html>",                // a real HTML page, not JSON
	} {
		if !strings.Contains(body, want) {
			t.Errorf("HTML body missing %q\nbody:\n%s", want, body)
		}
	}
	// Defence: must not leak the JSON error code shape into the HTML response.
	if strings.Contains(body, `"code":"FEATURE_NOT_AVAILABLE"`) {
		t.Error("HTML body must not contain JSON error envelope")
	}
}

func TestFeatureGateBrowser_Deny_JSONAccept_ReturnsJSONEnvelope(t *testing.T) {
	gate := configuredDenyingGate(t)
	next := &allowingHandler{}
	mw := gate.FeatureGateBrowser(FeatureOIDCSSO,
		"OIDC single sign-on", "https://vectismail.com/pricing")(next)

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login/google", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if next.called != 0 {
		t.Errorf("deny path must NOT invoke next; called %d times", next.called)
	}
	// JSON path keeps the existing FeatureGate contract: 403 (not 402),
	// FEATURE_NOT_AVAILABLE code, application/json content-type.
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	ct := rec.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		t.Errorf("Content-Type = %q, want application/json prefix", ct)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `"FEATURE_NOT_AVAILABLE"`) {
		t.Errorf("JSON body missing FEATURE_NOT_AVAILABLE code\nbody: %s", body)
	}
	if !strings.Contains(body, FeatureOIDCSSO) {
		t.Errorf("JSON body should name the gated feature; got %s", body)
	}
}

func TestFeatureGateBrowser_Deny_NoAccept_DefaultsToHTML(t *testing.T) {
	// When Accept is missing entirely (rare, but a hand-crafted request),
	// we side with the browser-friendly path. API clients that want JSON
	// can opt in by setting Accept explicitly.
	gate := configuredDenyingGate(t)
	mw := gate.FeatureGateBrowser(FeatureOIDCSSO, "OIDC single sign-on", "")(&allowingHandler{})

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login/google", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusPaymentRequired {
		t.Errorf("status = %d, want 402 (HTML branch)", rec.Code)
	}
	if !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", rec.Header().Get("Content-Type"))
	}
}

func TestFeatureGateBrowser_Deny_WildcardAccept_DefaultsToHTML(t *testing.T) {
	// curl's default Accept is "*/*". Treat as HTML so a curl operator
	// who hits the URL by hand sees the friendly page; scripts that
	// actually want JSON envelope handling must set Accept explicitly.
	gate := configuredDenyingGate(t)
	mw := gate.FeatureGateBrowser(FeatureOIDCSSO, "OIDC single sign-on", "")(&allowingHandler{})

	req := httptest.NewRequest(http.MethodGet, "/auth/oidc/login/google", nil)
	req.Header.Set("Accept", "*/*")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if rec.Code != http.StatusPaymentRequired {
		t.Errorf("status = %d, want 402", rec.Code)
	}
}

func TestFeatureGateBrowser_HTMLPage_EscapesUserInput(t *testing.T) {
	// featureLabel and upgradeURL come from server.go literals today, but
	// the renderer accepts them as strings. Pin that they're HTML-escaped
	// so a future caller passing user-derived data can't break out of the
	// page (defence in depth — there is no current path here, but it's
	// cheap to lock down).
	gate := configuredDenyingGate(t)
	mw := gate.FeatureGateBrowser(FeatureOIDCSSO,
		`OIDC <script>alert(1)</script>`,
		`https://example.com/?a=b&c="d"`,
	)(&allowingHandler{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("featureLabel must be HTML-escaped; raw <script> tag present")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Errorf("expected escaped <script>; body:\n%s", body)
	}
	if strings.Contains(body, `"d"`) && strings.Contains(body, `href="https://example.com/?a=b&c="d""`) {
		t.Error("upgradeURL must be HTML-escaped inside href attribute")
	}
}

// ---------------------------------------------------------------------------
// writeFeatureUpgradeHTML — direct render test (covers the expired branch
// which the deny tests above don't reach, since cache=nil yields err=nil).
// ---------------------------------------------------------------------------

func TestWriteFeatureUpgradeHTML_ExpiredBranch(t *testing.T) {
	rec := httptest.NewRecorder()
	writeFeatureUpgradeHTML(rec, "OIDC single sign-on", "https://vectismail.com/pricing", true)

	if rec.Code != http.StatusPaymentRequired {
		t.Errorf("status = %d, want 402", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "License expired") {
		t.Errorf("expected 'License expired' heading on expired branch; body:\n%s", body)
	}
	if !strings.Contains(body, "entitlement has expired") {
		t.Errorf("expected expired-specific copy; body:\n%s", body)
	}
}

func TestWriteFeatureUpgradeHTML_DefaultUpgradeURL(t *testing.T) {
	// Empty upgradeURL must fall back to the canonical pricing page so a
	// caller who forgets the third argument doesn't render a broken link.
	rec := httptest.NewRecorder()
	writeFeatureUpgradeHTML(rec, "OIDC single sign-on", "", false)
	body := rec.Body.String()
	if !strings.Contains(body, "https://vectismail.com/pricing") {
		t.Errorf("empty upgradeURL must fall back to canonical pricing URL; body:\n%s", body)
	}
}
