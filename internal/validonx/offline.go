package validonx

import (
	"time"

	"github.com/Veltara-Works/vectis/internal/license"
)

// OfflineLicense is the feature gate's view of the Pharlux-pattern offline
// verifier (internal/license). It pairs a refreshable JWKS [license.Provider]
// with the configured license token and VM policy, and answers a single
// question for the gate: "does the offline license currently entitle this
// install, and to what?"
//
// Verification is offline and stateless — a fresh [license.Verify] runs per
// query (Ed25519 verify is sub-millisecond), so the grace state machine is
// always evaluated against the current clock rather than a cached snapshot.
// The keyset is kept current out-of-band by a license.Refresher; this type only
// reads Provider.Current() and never touches the network on the query path.
type OfflineLicense struct {
	provider *license.Provider
	token    string
	policy   license.Policy
	now      func() time.Time // injectable clock for tests; defaults to time.Now
}

// NewOfflineLicense builds an OfflineLicense over p for the given token and
// policy (typically license.VMPolicy()). An empty token yields a verifier that
// always reports "not configured", so the gate falls through to the HTTP-resolve
// path unchanged.
func NewOfflineLicense(p *license.Provider, token string, policy license.Policy) *OfflineLicense {
	return &OfflineLicense{provider: p, token: token, policy: policy, now: time.Now}
}

// verdict verifies the configured token against the currently-loaded keyset.
// ok=false means "no offline authority to consult" — no token configured, no
// provider, or the keyset has not loaded yet — and the caller must fall through
// to the existing HTTP-resolve path. When ok=true the returned Verdict is
// authoritative (it may still be a REJECT, e.g. a tampered or wrong-issuer
// token, which the caller treats as "no offline entitlement").
func (o *OfflineLicense) verdict() (license.Verdict, bool) {
	if o == nil || o.token == "" || o.provider == nil {
		return license.Verdict{}, false
	}
	ks := o.provider.Current()
	if ks == nil {
		return license.Verdict{}, false
	}
	return license.Verify(o.token, ks, o.now(), o.policy), true
}

// OfflineStatus is a read-only snapshot of the offline JWT verifier's current
// view, for operator display on the admin License page. It never affects an
// entitlement decision — it just reports what the resilience layer sees.
type OfflineStatus struct {
	Configured bool   `json:"configured"`            // a token is present in secrets.yaml
	Active     bool   `json:"active"`                // currently entitling (ACCEPT + LIVE or IN_GRACE)
	Accepted   bool   `json:"accepted"`              // signature + claims verified
	Tier       string `json:"tier,omitempty"`        // resolved internal tier (e.g. "Pro")
	GraceState string `json:"grace_state,omitempty"` // LIVE | IN_GRACE | PAST_GRACE
	JWKSSource string `json:"jwks_source,omitempty"` // live | cache | embedded
	Reason     string `json:"reason,omitempty"`      // rejection reason when !Accepted
}

// Status returns a read-only snapshot of the offline verifier. Nil-safe: a nil
// receiver (or an empty token) reports Configured=false, the same as an install
// with no offline license, so the admin UI simply omits the offline panel.
func (o *OfflineLicense) Status() OfflineStatus {
	if o == nil || o.token == "" {
		return OfflineStatus{}
	}
	st := OfflineStatus{Configured: true}
	if o.provider != nil {
		st.JWKSSource = string(o.provider.Source())
	}
	v, ok := o.verdict()
	if !ok {
		// Token configured but the keyset has not loaded yet — report it as
		// configured-but-not-yet-active rather than fabricating a verdict.
		return st
	}
	st.Accepted = v.Accepted
	if v.Accepted {
		st.Tier = v.InternalTier
		st.GraceState = string(v.GraceState)
		st.Active = v.GraceState != license.GracePastGrace
	} else {
		st.Reason = v.Reason
	}
	return st
}

// featuresForTier maps a verifier-resolved internal tier name to the VM feature
// list the rest of the gate already reasons over (so the offline path reuses
// tierFromFeatures, HasFeature, etc. unchanged). VMPolicy emits "Pro"/
// "Enterprise" for a live pro/enterprise token and its DowngradeTier ("Free")
// past grace.
func featuresForTier(internalTier string) []string {
	switch internalTier {
	case "Enterprise":
		return EnterpriseFeatures
	case "Pro":
		return ProFeatures
	default:
		return FreeTierFeatures
	}
}

// featureInList reports whether feature appears in feats.
func featureInList(feats []string, feature string) bool {
	for _, f := range feats {
		if f == feature {
			return true
		}
	}
	return false
}
