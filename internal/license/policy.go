package license

import "time"

// Issuer is the only accepted `iss` value across the Veltara portfolio
// (contract §4). ValidonX is the canonical issuer of all license tokens.
const Issuer = "validonx"

// Limits is the parsed `limits` claim (contract §6). Each axis is
// independently optional; an absent pointer means "fall back to the tier
// default for this axis".
type Limits struct {
	HostsMax      *uint32
	RetentionDays *uint32
}

// GraceModel is the product-specific expiry/grace policy. The window-based
// model here matches Pharlux's verifier (contract §9): a fixed grace window
// after `exp`, then a downgrade to a fallback tier with empty entitlements.
//
// Both products use this window shape, but with different intent and window
// sizes. For Vectis Mail the window is a MODEST resilience cushion, not the
// subscription grace: VM's HTTP-resolve path is the primary entitlement source
// and owns the 21-day past_due grace, so the offline JWT only needs a short
// post-exp cushion before deferring back to that path (decision, Ian
// 2026-06-21). See [VMGraceCushion] and validonx.offlineFeatures.
type GraceModel struct {
	// Window is the grace duration after exp during which the paid tier is
	// preserved. After exp+Window, the token downgrades.
	Window time.Duration
	// DowngradeTier is the internal tier returned past grace (e.g. "Community").
	DowngradeTier string
}

// classify returns the grace state for now relative to exp. A clock before
// the Unix epoch (negative now) is treated as far-future / held-expired:
// a bad clock must never keep a paid tier alive (contract §9, fail closed).
func (g GraceModel) classify(nowUnix, expUnix int64) GraceState {
	if nowUnix < 0 {
		return GracePastGrace
	}
	switch {
	case nowUnix < expUnix:
		return GraceLive
	case nowUnix < expUnix+int64(g.Window/time.Second):
		return GraceInGrace
	default:
		return GracePastGrace
	}
}

// TierMapper resolves a `tier` claim plus the parsed `limits` override into
// an internal tier name and an entitlements map. ok=false means the tier is
// not recognised by this policy (-> REJECT UnknownTierClaim). The mapper owns
// the product's entitlement-key namespace and its limits-override semantics,
// since "unlimited" representation and key names differ per product.
type TierMapper func(tier string, limits Limits) (internalTier string, entitlements map[string]string, ok bool)

// Policy carries the product-specific parts of verification. The core
// algorithm (parse, alg-pin, kid-select, signature, claim presence, iss/aud)
// is shared; Policy injects audience, tier mapping, and grace.
type Policy struct {
	// Audience is the required value that the token's `aud` must contain.
	Audience string
	// MapTier resolves the tier claim + limits to a tier and entitlements.
	MapTier TierMapper
	// Grace is the expiry/grace model applied after a successful map.
	Grace GraceModel
}

// ---- Pharlux policy (drives the conformance vectors) -----------------------

// pharluxLimitDefaults holds the per-tier default caps. A nil pointer means
// the axis is unlimited for that tier (key omitted from entitlements).
type pharluxLimitDefaults struct {
	hostsMax      *uint32
	retentionDays *uint32
	binaryDist    bool
}

func u32(v uint32) *uint32 { return &v }

var pharluxTiers = map[string]pharluxLimitDefaults{
	"team":                    {hostsMax: u32(25), retentionDays: u32(30), binaryDist: false},
	"business":                {hostsMax: u32(250), retentionDays: u32(90), binaryDist: false},
	"scale":                   {hostsMax: nil, retentionDays: nil, binaryDist: true},
	"commercial-license-only": {hostsMax: nil, retentionDays: nil, binaryDist: false},
}

var pharluxInternalTier = map[string]string{
	"team":                    "Professional",
	"business":                "Enterprise",
	"scale":                   "Custom",
	"commercial-license-only": "Custom",
}

// PharluxPolicy returns the policy that mirrors Pharlux's canonical verifier.
// It exists primarily to run the conformance vectors: aud="pharlux", the four
// frozen tiers, pharlux.* entitlement keys, and a fixed 24h grace window with
// a "Community" downgrade. A green run under this policy proves the shared
// core is bit-compatible with the canonical implementation.
func PharluxPolicy() Policy {
	return Policy{
		Audience: "pharlux",
		Grace:    GraceModel{Window: 24 * time.Hour, DowngradeTier: "Community"},
		MapTier: func(tier string, limits Limits) (string, map[string]string, bool) {
			def, ok := pharluxTiers[tier]
			if !ok {
				return "", nil, false
			}
			ent := map[string]string{
				"pharlux.tier":                         tier,
				"pharlux.features.commercial-use":      "true",
				"pharlux.features.binary-distribution": boolStr(def.binaryDist),
			}
			// Resolve each limit axis: claim override wins, else tier default,
			// else omit the key ("unlimited").
			if h := resolveLimit(limits.HostsMax, def.hostsMax); h != nil {
				ent["pharlux.limits.hosts.max"] = u32Str(*h)
			}
			if r := resolveLimit(limits.RetentionDays, def.retentionDays); r != nil {
				ent["pharlux.limits.retention.days"] = u32Str(*r)
			}
			return pharluxInternalTier[tier], ent, true
		},
	}
}

// ---- Vectis Mail policy ----------------------------------------------------

// VMGraceCushion is the window after a token's exp during which the offline
// verifier still honours the token's tier (GraceInGrace) before downgrading
// (GracePastGrace). It is deliberately MODEST.
//
// VM's licensing model is HTTP-resolve-primary, offline-JWT-as-resilience
// (decision, Ian 2026-06-21): online installs entitle via the ValidonX
// HTTP-resolve path, which owns the 21-day past_due subscription grace —
// ValidonX keeps minting tier:"pro" right through it (plan §4.2 option (c)).
// The offline JWT is the air-gap/outage layer. So this cushion does not need to
// span the subscription grace; it only bridges the brief gap between a token's
// 96h exp and either the next re-mint or a fall-through to HTTP-resolve. Past
// the cushion the gate falls through to the primary path rather than pinning the
// install to Free (see validonx.offlineFeatures). Subscription `status` is read
// from the resolve response, not carried as a token claim, so it plays no part
// in this offline classification.
const VMGraceCushion = 24 * time.Hour

// VMPolicy returns Vectis Mail's production policy: aud="vectis-mail", the VM
// tier map (vectis-licensing-plan.md §4.1), and VM's grace cushion (see
// VMGraceCushion for why it is a modest post-exp window rather than the full
// subscription grace).
func VMPolicy() Policy {
	return Policy{
		Audience: "vectis-mail",
		Grace:    GraceModel{Window: VMGraceCushion, DowngradeTier: "Free"},
		MapTier: func(tier string, _ Limits) (string, map[string]string, bool) {
			switch tier {
			case "pro":
				return "Pro", map[string]string{
					"vectis.tier":                          "pro",
					"vectis.features.unlimited-domains":    "true",
					"vectis.features.unlimited-mailboxes":  "true",
					"vectis.features.per-domain-analytics": "true",
					"vectis.features.advanced-spam":        "true",
					"vectis.features.oidc-sso":             "true",
					"vectis.features.priority-support":     "true",
				}, true
			case "enterprise":
				// Enterprise is a superset of Pro plus the Enterprise-only
				// features. The gate derives the authoritative entitlement set
				// from InternalTier ("Enterprise" -> validonx.EnterpriseFeatures,
				// which includes scim); this map is the display-only entitlement
				// view surfaced by `vectis license verify`. It lists only shipped,
				// entitled features — advanced_deliverability is a roadmap item
				// (not in EnterpriseFeatures) so it is deliberately omitted.
				return "Enterprise", map[string]string{
					"vectis.tier":                          "enterprise",
					"vectis.features.unlimited-domains":    "true",
					"vectis.features.unlimited-mailboxes":  "true",
					"vectis.features.per-domain-analytics": "true",
					"vectis.features.advanced-spam":        "true",
					"vectis.features.oidc-sso":             "true",
					"vectis.features.priority-support":     "true",
					"vectis.features.saml-sso":             "true",
					"vectis.features.sla":                  "true",
					"vectis.features.dsar":                 "true",
					"vectis.features.scim-provisioning":    "true",
				}, true
			default:
				return "", nil, false
			}
		},
	}
}

// resolveLimit applies override-then-default-then-omit for one axis.
func resolveLimit(override, def *uint32) *uint32 {
	if override != nil {
		return override
	}
	return def
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
