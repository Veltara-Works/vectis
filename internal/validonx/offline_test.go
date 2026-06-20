package validonx

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/license"
)

// --- test signing helpers --------------------------------------------------

const testKid = "test-vm-2026"

// newTestProvider builds a license.Provider backed solely by an embedded JWKS
// containing pub under testKid (no live/cache layers), and loads it. The
// matching private key is returned for signing test tokens.
func newTestProvider(t *testing.T) (*license.Provider, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	jwks, err := json.Marshal(map[string]any{
		"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
			"kid": testKid,
			"x":   base64.RawURLEncoding.EncodeToString(pub),
		}},
	})
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	p := license.NewProvider(&license.Resolver{Embedded: jwks})
	if _, err := p.Refresh(context.Background()); err != nil {
		t.Fatalf("provider refresh: %v", err)
	}
	return p, priv
}

// signVMToken builds and signs a vectis-mail license JWT with the given tier
// and exp, using kid testKid so newTestProvider's keyset verifies it.
func signVMToken(t *testing.T, priv ed25519.PrivateKey, tier string, iat, exp time.Time) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	header := enc(map[string]string{"alg": "EdDSA", "typ": "JWT", "kid": testKid})
	payload := enc(map[string]any{
		"iss":  license.Issuer,
		"sub":  "cust_test",
		"aud":  "vectis-mail",
		"iat":  iat.Unix(),
		"exp":  exp.Unix(),
		"jti":  "11111111-1111-4111-8111-111111111111",
		"tier": tier,
	})
	signingInput := header + "." + payload
	sig := ed25519.Sign(priv, []byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// gateWithOffline returns an unconfigured-HTTP gate carrying an offline license
// whose clock is pinned to `now`, so grace classification is deterministic.
func gateWithOffline(t *testing.T, token string, p *license.Provider, now time.Time) *FeatureGateService {
	t.Helper()
	gate := NewFeatureGateService(nil, nil, testLogger())
	o := NewOfflineLicense(p, token, license.VMPolicy())
	o.now = func() time.Time { return now }
	gate.SetOfflineLicense(o)
	return gate
}

// --- tests -----------------------------------------------------------------

// TestOfflineLicense_ProToken_AllowsProFeature is the core JWT-wins-when-present
// path: a valid live pro token entitles a Pro feature even though the ValidonX
// HTTP client is unconfigured (which would otherwise deny).
func TestOfflineLicense_ProToken_AllowsProFeature(t *testing.T) {
	p, priv := newTestProvider(t)
	now := time.Unix(1_700_000_000, 0)
	token := signVMToken(t, priv, "pro", now.Add(-time.Hour), now.Add(72*time.Hour))
	gate := gateWithOffline(t, token, p, now)

	next := &allowingHandler{}
	mw := gate.FeatureGate(FeatureOIDCSSO)(next)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/oidc", nil))

	if next.called != 1 {
		t.Errorf("pro token must allow a Pro feature; next called %d", next.called)
	}
	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if !gate.HasFeature(context.Background(), FeatureAdvancedSpam) {
		t.Error("HasFeature(advanced_spam) = false, want true under pro token")
	}
	if tier, _ := gate.ResolveTier(context.Background()); tier != TierPro {
		t.Errorf("ResolveTier = %q, want %q", tier, TierPro)
	}
}

// TestOfflineLicense_ProToken_DeniesEnterpriseFeature: a pro token wins, but
// only grants Pro features — an Enterprise feature is still denied.
func TestOfflineLicense_ProToken_DeniesEnterpriseFeature(t *testing.T) {
	p, priv := newTestProvider(t)
	now := time.Unix(1_700_000_000, 0)
	token := signVMToken(t, priv, "pro", now.Add(-time.Hour), now.Add(72*time.Hour))
	gate := gateWithOffline(t, token, p, now)

	next := &allowingHandler{}
	mw := gate.FeatureGate(FeatureSAMLSSO)(next)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/admin/saml", nil))

	if next.called != 0 {
		t.Errorf("pro token must NOT grant an Enterprise feature; next called %d", next.called)
	}
	if rec.Code != http.StatusForbidden {
		t.Errorf("status = %d, want 403", rec.Code)
	}
}

// TestOfflineLicense_PastGrace_FallsThrough: a token past exp+grace has nothing
// left to assert, so the offline source reports NO authority and the gate falls
// through to the HTTP-resolve path (unconfigured here, hence Free/deny) rather
// than authoritatively pinning the install to Free. This is the
// HTTP-resolve-primary / offline-JWT-as-resilience behaviour: a lapsed
// resilience token defers to the primary path, which on a healthy subscription
// would still entitle the box.
func TestOfflineLicense_PastGrace_FallsThrough(t *testing.T) {
	p, priv := newTestProvider(t)
	now := time.Unix(1_700_000_000, 0)
	// exp 48h ago, well past the 24h grace cushion.
	token := signVMToken(t, priv, "pro", now.Add(-96*time.Hour), now.Add(-48*time.Hour))
	gate := gateWithOffline(t, token, p, now)

	if _, ok := gate.offlineFeatures(); ok {
		t.Error("past-grace token must report no offline authority (fall through to http-resolve)")
	}
	if gate.HasFeature(context.Background(), FeatureOIDCSSO) {
		t.Error("past-grace token must not grant Pro features")
	}
	if tier, _ := gate.ResolveTier(context.Background()); tier != TierFree {
		t.Errorf("ResolveTier = %q, want %q after grace", tier, TierFree)
	}
}

// TestOfflineLicense_InGrace_StillEntitles: a token expired within the grace
// cushion still entitles its tier (the resilience layer holds the tier briefly
// past exp to bridge a missed re-mint).
func TestOfflineLicense_InGrace_StillEntitles(t *testing.T) {
	p, priv := newTestProvider(t)
	now := time.Unix(1_700_000_000, 0)
	// exp 1h ago — inside the 24h cushion.
	token := signVMToken(t, priv, "pro", now.Add(-97*time.Hour), now.Add(-time.Hour))
	gate := gateWithOffline(t, token, p, now)

	feats, ok := gate.offlineFeatures()
	if !ok {
		t.Fatal("in-grace token must still carry offline authority")
	}
	if !featureInList(feats, FeatureOIDCSSO) {
		t.Error("in-grace pro token must still grant Pro features")
	}
}

// TestOfflineLicense_TamperedToken_FallsThrough: a token rejected by Verify
// (here, signature mutated) yields no offline authority, so the gate falls
// through to the HTTP-resolve path — unconfigured here, hence Free/deny.
func TestOfflineLicense_TamperedToken_FallsThrough(t *testing.T) {
	p, priv := newTestProvider(t)
	now := time.Unix(1_700_000_000, 0)
	token := signVMToken(t, priv, "pro", now.Add(-time.Hour), now.Add(72*time.Hour))
	// Deterministically corrupt the final signature character. A fixed
	// replacement (e.g. "AA") would equal the original tail ~1/4096 of the time
	// since the signing key is random per run, making the "tamper" a no-op and
	// the test flaky. Swapping to a guaranteed-different base64url char with
	// zero padding bits ('A'=0 / 'Q'=16, both strict-decodable) keeps the
	// failure mode a clean signature mismatch.
	last := token[len(token)-1]
	swap := byte('A')
	if last == 'A' {
		swap = 'Q'
	}
	tampered := token[:len(token)-1] + string(swap)

	gate := gateWithOffline(t, tampered, p, now)

	if gate.HasFeature(context.Background(), FeatureOIDCSSO) {
		t.Error("tampered token must not grant features (fall through to Free)")
	}
	if _, ok := gate.offlineFeatures(); ok {
		t.Error("offlineFeatures must report no authority for a rejected token")
	}
}

// TestOfflineLicense_KeysetNotLoaded_FallsThrough: before the provider has any
// keyset, the offline source must report no authority rather than mis-deny.
func TestOfflineLicense_KeysetNotLoaded_FallsThrough(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	_ = pub
	now := time.Unix(1_700_000_000, 0)
	token := signVMToken(t, priv, "pro", now.Add(-time.Hour), now.Add(72*time.Hour))

	// Provider never refreshed → Current() is nil.
	p := license.NewProvider(&license.Resolver{})
	gate := gateWithOffline(t, token, p, now)

	if _, ok := gate.offlineFeatures(); ok {
		t.Error("offlineFeatures must report no authority when keyset unloaded")
	}
}

// TestOfflineLicense_NilOffline_UnchangedBehaviour: with no offline license
// set, the gate must behave exactly as the HTTP-resolve-only design — an
// unconfigured gate denies a Pro feature.
func TestOfflineLicense_NilOffline_UnchangedBehaviour(t *testing.T) {
	gate := NewFeatureGateService(nil, nil, testLogger())
	if _, ok := gate.offlineFeatures(); ok {
		t.Error("offlineFeatures must report no authority when offline is nil")
	}
	if gate.HasFeature(context.Background(), FeatureOIDCSSO) {
		t.Error("nil-offline gate must deny Pro features")
	}
}
