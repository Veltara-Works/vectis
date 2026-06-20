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

// featuresForTier maps a verifier-resolved internal tier name to the VM feature
// list the rest of the gate already reasons over (so the offline path reuses
// tierFromFeatures, HasFeature, etc. unchanged). VMPolicy emits "Pro" for a
// live pro token and its DowngradeTier ("Free") past grace; "Enterprise" is
// handled for forward-compatibility though VMPolicy does not emit it yet.
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
