// Package license implements a native-Go verifier for ValidonX-issued
// license tokens (Ed25519 JWTs), following the frozen Pharlux licensing
// token contract (see docs/notes/vectis-licensing-plan.md and the Pharlux
// LICENSE_TOKEN_CONTRACT.md).
//
// The verifier is split into a product-agnostic core (token parse, EdDSA
// algorithm pinning, fail-closed key selection, signature verification,
// claim validation, limits-override) and an injected [Policy] carrying the
// product-specific parts: the expected audience, the tier->entitlements
// mapping, and the grace model. This lets a single implementation be
// proven bit-compatible against the canonical Rust verifier using Pharlux's
// conformance vectors (run under [PharluxPolicy]) while Vectis Mail runs the
// same core under [VMPolicy] with its own audience, tiers, and grace policy.
//
// Verification is fully offline-capable: Verify takes (token, keyset, now)
// and performs no network I/O. Key distribution (live JWKS -> on-disk cache
// -> embedded fallback) is a separate concern layered above Verify.
package license

// GraceState classifies a token by the relationship between the evaluation
// time and its `exp`, per the grace state machine (contract §9).
type GraceState string

const (
	// GraceLive: now < exp. The token's own tier and full entitlements apply.
	GraceLive GraceState = "LIVE"
	// GraceInGrace: exp <= now < exp+window. The paid tier is preserved.
	GraceInGrace GraceState = "IN_GRACE"
	// GracePastGrace: now >= exp+window. Downgrade to the policy's fallback
	// tier with empty entitlements.
	GracePastGrace GraceState = "PAST_GRACE"
)

// Verdict is the result of verifying a token. Exactly one of Accepted==true
// (with InternalTier/Entitlements/GraceState populated) or Accepted==false
// (with Reason populated) holds.
type Verdict struct {
	Accepted bool
	// Reason is the typed rejection reason when Accepted is false. It mirrors
	// the canonical verifier's reason strings closely enough to drive the
	// conformance vectors (e.g. "bad signature", "UnknownKid: <kid>",
	// "UnknownTierClaim", "issuer mismatch", "audience mismatch",
	// "MissingKid", "algorithm not allowed", "malformed").
	Reason string

	// GraceState is the classification used to resolve the effective tier.
	GraceState GraceState
	// InternalTier is the resolved internal tier name (e.g. "Professional",
	// or the policy's downgrade tier such as "Community" past grace).
	InternalTier string
	// Entitlements is the resolved entitlements map. Values are strings
	// (e.g. "true"/"false", numeric strings) to match the canonical map
	// shape. An "unlimited" axis is represented by an ABSENT key, never a
	// sentinel value (contract §5).
	Entitlements map[string]string
}

func reject(reason string) Verdict { return Verdict{Accepted: false, Reason: reason} }
