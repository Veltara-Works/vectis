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
