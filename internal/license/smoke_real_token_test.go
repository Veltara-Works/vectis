package license

import (
	"context"
	"testing"
	"time"
)

// TestRealValidonXProductionToken is a real-envelope regression test: it feeds
// the verifier an actual ValidonX-minted vectis-mail production token (the
// 2026-06-21 cross-repo smoke token, aud:"vectis-mail" tier:"pro", signed with
// the production kid validonx-2026-05) and verifies it against the EMBEDDED
// keyset we ship — i.e. the exact bytes an air-gapped install would use, no
// network. This locks the contract end-to-end: our embedded key + verifier
// accept ValidonX's real signature, claim shape, and fractional NumericDates.
//
// The clock is pinned just after the token's iat so the assertion is stable
// after the token's 96h exp passes (the signature stays valid forever; only the
// grace classification depends on the clock).
func TestRealValidonXProductionToken(t *testing.T) {
	// Real compact JWS minted by ValidonX against a sandbox holder tenant
	// (sub c028523d-…, placeholder customer_email), 2026-06-21.
	const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6InZhbGlkb254LTIwMjYtMDUifQ.eyJpc3MiOiJ2YWxpZG9ueCIsImF1ZCI6InZlY3Rpcy1tYWlsIiwic3ViIjoiYzAyODUyM2QtZmE3Mi00MjdjLWE2YTctNDFmYjRjMThlY2JhIiwianRpIjoiMjA0ZjZiZjUtZjg0ZC00ZTc2LTg4M2MtYzY4Y2JiNjVmZjA5IiwiaWF0IjoxNzgxOTczOTM1LjYyMDEyOSwiZXhwIjoxNzgyMzE5NTM1LjYyMDEyOSwidGllciI6InBybyIsImN1c3RvbWVyX2VtYWlsIjoic21va2VAZXhhbXBsZS50ZXN0In0.Sy51vzBkPTpgFsHiqrNQWiSe49T9ks8EujN_PjKCOZUl4EcHTcAat7vyD-phP7o8rlQAqFwJ3svBHnhiZD-hAA"

	// Resolve against the embedded keyset only (no live, no cache) — proves the
	// shipped fallback key verifies a real production signature.
	ks, src, err := (&Resolver{Embedded: embeddedJWKS}).Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve embedded keyset: %v", err)
	}
	if src != SourceEmbedded {
		t.Fatalf("source = %q, want embedded", src)
	}

	now := time.Unix(1781973936, 0) // 1s after the token's iat → LIVE
	v := Verify(token, ks, now, VMPolicy())

	if !v.Accepted {
		t.Fatalf("real production token rejected: %s", v.Reason)
	}
	if v.GraceState != GraceLive {
		t.Errorf("grace = %s, want LIVE", v.GraceState)
	}
	if v.InternalTier != "Pro" {
		t.Errorf("tier = %q, want Pro", v.InternalTier)
	}
	if v.Entitlements["vectis.features.oidc-sso"] != "true" {
		t.Errorf("expected oidc-sso entitlement, got %v", v.Entitlements)
	}
}

// TestRealValidonXEnterpriseToken is the real-envelope Enterprise counterpart
// to TestRealValidonXProductionToken: it feeds the verifier an actual
// ValidonX-minted vectis-mail token (aud:"vectis-mail" tier:"enterprise",
// production kid validonx-2026-05) and verifies it against the EMBEDDED keyset,
// proving the air-gap path accepts ValidonX's real Enterprise signature and
// that VMPolicy maps tier:"enterprise" → Enterprise with the scim entitlement.
//
// Safe to commit because the token's validity window is ENTIRELY IN THE PAST
// (iat 2026-06-18T00:00:00Z, exp 2026-06-22T00:00:00Z). The signature is valid
// forever, but the grace classification depends on the clock — so we pin a
// clock INSIDE the original live window to assert the LIVE/Enterprise verdict,
// and separately assert that at a CURRENT clock the same token is past grace
// and unlocks nothing. An expired token cannot be pasted into a secrets.yaml
// [license] block to unlock Enterprise offline (see
// feedback_no_live_license_tokens_in_fixtures), which is why ValidonX minted it
// already-expired for this fixture.
func TestRealValidonXEnterpriseToken(t *testing.T) {
	// Real compact JWS minted by ValidonX against a sandbox holder tenant
	// (sub c028523d-…, placeholder customer_email), already-expired window.
	const token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6InZhbGlkb254LTIwMjYtMDUifQ.eyJpc3MiOiJ2YWxpZG9ueCIsImF1ZCI6InZlY3Rpcy1tYWlsIiwic3ViIjoiYzAyODUyM2QtZmE3Mi00MjdjLWE2YTctNDFmYjRjMThlY2JhIiwianRpIjoiMzQ5MWJlNmMtNWIyMC00NzQzLWI5MTMtOWQwMDdmNTQ3N2IwIiwiaWF0IjoxNzgxNzQwODAwLCJleHAiOjE3ODIwODY0MDAsInRpZXIiOiJlbnRlcnByaXNlIiwiY3VzdG9tZXJfZW1haWwiOiJzbW9rZUBleGFtcGxlLnRlc3QifQ.H9Uj0OKYgwPSj0mdWlc2h7mdwYXdUrRL-7_6r4lmBG7K_ELqFmpZOMyERPjAFuegYIoDUh6NL5EjZ2QBqZD8BA"

	ks, src, err := (&Resolver{Embedded: embeddedJWKS}).Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve embedded keyset: %v", err)
	}
	if src != SourceEmbedded {
		t.Fatalf("source = %q, want embedded", src)
	}

	// Clock pinned mid-window (2026-06-20T00:00:00Z, between iat and exp) → the
	// real signature is accepted and the token classifies LIVE/Enterprise.
	live := time.Unix(1781913600, 0)
	v := Verify(token, ks, live, VMPolicy())
	if !v.Accepted {
		t.Fatalf("real enterprise token rejected in-window: %s", v.Reason)
	}
	if v.GraceState != GraceLive {
		t.Errorf("grace = %s, want LIVE", v.GraceState)
	}
	if v.InternalTier != "Enterprise" {
		t.Errorf("tier = %q, want Enterprise", v.InternalTier)
	}
	if v.Entitlements["vectis.features.scim-provisioning"] != "true" {
		t.Errorf("expected scim-provisioning entitlement, got %v", v.Entitlements)
	}
	if v.Entitlements["vectis.features.saml-sso"] != "true" {
		t.Errorf("expected saml-sso entitlement, got %v", v.Entitlements)
	}

	// Belt-and-braces on why this is safe to commit: at a clock past exp+grace
	// (the token has been expired since 2026-06-23T00:00:00Z) the SAME real
	// token is accepted-but-downgraded — Free tier, no entitlements. A paste of
	// this fixture into a live install unlocks nothing.
	expired := time.Unix(1782259200, 0) // 2026-06-24T00:00:00Z, > exp+24h cushion
	ev := Verify(token, ks, expired, VMPolicy())
	if !ev.Accepted {
		t.Fatalf("real enterprise token should still verify (signature valid): %s", ev.Reason)
	}
	if ev.GraceState != GracePastGrace {
		t.Errorf("past-exp grace = %s, want PAST_GRACE", ev.GraceState)
	}
	if ev.InternalTier != "Free" {
		t.Errorf("past-grace tier = %q, want Free", ev.InternalTier)
	}
	if len(ev.Entitlements) != 0 {
		t.Errorf("past-grace entitlements must be empty, got %v", ev.Entitlements)
	}
}

// TestVMPolicyResolvesEnterpriseTier locks the offline Enterprise tier mapping:
// VMPolicy must resolve tier:"enterprise" → InternalTier "Enterprise" with a
// display-entitlement view that advertises only shipped Enterprise features
// (incl. scim), while still mapping "pro" and rejecting unknown tiers. The
// authoritative gate set is derived from InternalTier →
// validonx.EnterpriseFeatures (see validonx.TestOfflineEnterpriseTierGrantsSCIM).
//
// This is the synthetic counterpart to TestRealValidonXEnterpriseToken above,
// kept for fast tier-map coverage independent of the real fixture's clock.
func TestVMPolicyResolvesEnterpriseTier(t *testing.T) {
	tier, ent, ok := VMPolicy().MapTier("enterprise", Limits{})
	if !ok {
		t.Fatal("enterprise tier must be recognised by VMPolicy")
	}
	if tier != "Enterprise" {
		t.Errorf("internal tier = %q, want Enterprise", tier)
	}
	if ent["vectis.tier"] != "enterprise" {
		t.Errorf("vectis.tier = %q, want enterprise", ent["vectis.tier"])
	}
	for _, k := range []string{"vectis.features.scim-provisioning", "vectis.features.saml-sso", "vectis.features.dsar"} {
		if ent[k] != "true" {
			t.Errorf("expected entitlement %q=true, got %q", k, ent[k])
		}
	}
	// Roadmap/unshipped features must not be advertised (claims integrity).
	if _, present := ent["vectis.features.advanced-deliverability"]; present {
		t.Error("must not advertise advanced-deliverability (unshipped roadmap item)")
	}
	// Pro still maps; unknown tiers still reject.
	if pt, _, pok := VMPolicy().MapTier("pro", Limits{}); !pok || pt != "Pro" {
		t.Errorf("pro mapping regressed: tier=%q ok=%v", pt, pok)
	}
	if _, _, uok := VMPolicy().MapTier("nonsense", Limits{}); uok {
		t.Error("unknown tier must be rejected (UnknownTierClaim)")
	}
}
