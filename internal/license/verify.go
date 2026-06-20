package license

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Leeway is the clock tolerance applied to time-based claim validation
// (contract §8 step 4). The grace state machine (§9) is what governs the
// effective tier; Leeway covers small clock skew on the issue-time side.
const Leeway = 60 * time.Second

// jwsHeader is the JOSE header. `alg` is pinned to EdDSA by the verifier and
// is never trusted to select the algorithm (algorithm-confusion defence).
type jwsHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// claims is the license payload. Time claims are float64 to tolerate the
// fractional NumericDates emitted by the issuer's JWT library (RFC 7519 §2);
// they are truncated to integer seconds for any arithmetic.
type claims struct {
	Iss    string          `json:"iss"`
	Sub    string          `json:"sub"`
	Aud    json.RawMessage `json:"aud"`
	Iat    *float64        `json:"iat"`
	Exp    *float64        `json:"exp"`
	Jti    string          `json:"jti"`
	Tier   string          `json:"tier"`
	Limits *struct {
		HostsMax      *uint32 `json:"hosts_max"`
		RetentionDays *uint32 `json:"retention_days"`
	} `json:"limits"`
}

// Verify checks token against the trusted keyset at time now under policy,
// returning an ACCEPT Verdict (with effective tier + entitlements) or a typed
// REJECT. It performs no I/O. The algorithm mirrors contract §8:
//
//  1. parse header; require alg==EdDSA and a non-empty kid (fail closed);
//  2. select the trusted key by kid (no match -> UnknownKid);
//  3. verify the Ed25519 signature over header.payload;
//  4. parse claims; require presence of iss,sub,aud,iat,exp,jti, iss==Issuer,
//     and aud contains policy.Audience;
//  5. map tier (unknown -> UnknownTierClaim) and apply limits overrides;
//  6. apply the grace state machine to resolve the effective tier.
func Verify(token string, ks *KeySet, now time.Time, policy Policy) Verdict {
	// Guard the exported surface: a nil keyset or an incompletely-built
	// Policy is operator misconfiguration, not a valid token. Fail closed
	// with a REJECT rather than panicking the calling process.
	if ks == nil || policy.MapTier == nil {
		return reject("misconfigured verifier")
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return reject("malformed")
	}
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	// 1. Header: pin alg, require kid.
	headerRaw, err := base64.RawURLEncoding.DecodeString(headerB64)
	if err != nil {
		return reject("malformed")
	}
	var hdr jwsHeader
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		return reject("malformed")
	}
	if hdr.Alg != "EdDSA" {
		return reject("algorithm not allowed")
	}
	if hdr.Kid == "" {
		return reject("MissingKid")
	}

	// 2. Key selection (fail closed).
	pub, ok := ks.lookup(hdr.Kid)
	if !ok {
		return reject("UnknownKid: " + hdr.Kid)
	}

	// 3. Signature over the exact received header.payload segments.
	// Decode strictly: a non-canonical base64url signature (e.g. non-zero
	// trailing padding bits) is a tampered signature, not a parse nicety.
	// Go's default RawURLEncoding silently ignores those bits, which would
	// let a flipped final char decode to the same bytes and verify — so we
	// pin .Strict() and fold a decode failure into "bad signature".
	sig, err := base64.RawURLEncoding.Strict().DecodeString(sigB64)
	if err != nil {
		return reject("bad signature")
	}
	signingInput := headerB64 + "." + payloadB64
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return reject("bad signature")
	}

	// 4. Claims.
	payloadRaw, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return reject("malformed")
	}
	var c claims
	if err := json.Unmarshal(payloadRaw, &c); err != nil {
		return reject("malformed")
	}
	if c.Sub == "" || c.Jti == "" || c.Iat == nil || c.Exp == nil || c.Aud == nil {
		return reject("malformed")
	}
	if c.Iss != Issuer {
		return reject("issuer mismatch")
	}
	if !audienceContains(c.Aud, policy.Audience) {
		return reject("audience mismatch")
	}

	// Time-based claim validation (contract §8 step 4): a token issued more
	// than Leeway into the future relative to our clock is not yet valid.
	// `exp` is deliberately NOT hard-checked here — the grace state machine
	// (step 6) owns expiry. nowUnix is reused for that classification.
	nowUnix := now.Unix()
	if int64(*c.Iat) > nowUnix+int64(Leeway/time.Second) {
		return reject("issued in the future")
	}

	// 5. Tier + limits.
	limits := Limits{}
	if c.Limits != nil {
		limits.HostsMax = c.Limits.HostsMax
		limits.RetentionDays = c.Limits.RetentionDays
	}
	internalTier, entitlements, ok := policy.MapTier(c.Tier, limits)
	if !ok {
		return reject("UnknownTierClaim")
	}

	// 6. Grace.
	expUnix := int64(*c.Exp) // truncate fractional seconds
	state := policy.Grace.classify(nowUnix, expUnix)
	if state == GracePastGrace {
		internalTier = policy.Grace.DowngradeTier
		entitlements = map[string]string{}
	}

	return Verdict{
		Accepted:     true,
		GraceState:   state,
		InternalTier: internalTier,
		Entitlements: entitlements,
	}
}

// audienceContains reports whether the `aud` claim (a bare string or an array
// of strings, per RFC 7519 §4.1.3) includes want.
func audienceContains(raw json.RawMessage, want string) bool {
	var single string
	if err := json.Unmarshal(raw, &single); err == nil {
		return single == want
	}
	var multi []string
	if err := json.Unmarshal(raw, &multi); err == nil {
		for _, a := range multi {
			if a == want {
				return true
			}
		}
	}
	return false
}

func u32Str(v uint32) string { return strconv.FormatUint(uint64(v), 10) }
