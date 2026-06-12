package validonx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestFeatureGate_Unconfigured_NonFree_Denies pins the v0.1.6 fix to the
// route-level FeatureGate middleware (the path used by analytics, advanced
// spam, etc.). Pre-v0.1.6 an unconfigured ValidonX let every Pro/Enterprise
// route pass; v0.1.6 treats unconfigured as Free tier and denies.
// See feedback_featuregate_unconfigured_bypass.md.
func TestFeatureGate_Unconfigured_NonFree_Denies(t *testing.T) {
	gate := NewFeatureGateService(nil, nil, testLogger())

	next := &allowingHandler{}
	mw := gate.FeatureGate(FeatureAnalytics)(next)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/domains/x/analytics", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if next.called != 0 {
		t.Errorf("unconfigured gate must NOT pass through Pro features; next called %d times", next.called)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
	var body featureErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("response not JSON: %v", err)
	}
	if body.Error.Code != ErrFeatureNotAvailable {
		t.Errorf("error code = %q, want %q", body.Error.Code, ErrFeatureNotAvailable)
	}
}

// TestFeatureGate_Unconfigured_FreeTier_Allows verifies the partial-allow
// path: basic_mail still passes on an unconfigured gate (Free tier has at
// least basic_mail).
func TestFeatureGate_Unconfigured_FreeTier_Allows(t *testing.T) {
	gate := NewFeatureGateService(nil, nil, testLogger())

	next := &allowingHandler{}
	mw := gate.FeatureGate(FeatureBasicMail)(next)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/domains", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if next.called != 1 {
		t.Errorf("basic_mail must pass through on unconfigured gate; next called %d times", next.called)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
}

// TestFeatureGate_Unconfigured_EnterpriseFeature_Denies pins the same
// behaviour for Enterprise-only features. Catch-all in case a Free install
// somehow has a route registered for an Enterprise feature.
func TestFeatureGate_Unconfigured_EnterpriseFeature_Denies(t *testing.T) {
	gate := NewFeatureGateService(nil, nil, testLogger())

	next := &allowingHandler{}
	mw := gate.FeatureGate(FeatureSLA)(next)

	req := httptest.NewRequest(http.MethodPost, "/admin/enterprise", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	if next.called != 0 {
		t.Errorf("unconfigured gate must NOT pass through Enterprise features; next called %d times", next.called)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}
