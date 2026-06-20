package license

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"
)

// conformanceFile is the Pharlux-issued vector pack (Phase-1 frozen contract),
// copied verbatim from the Pharlux handoff. Driving the verifier off it proves
// the shared core is bit-compatible with the canonical Rust verifier.
const conformanceFile = "testdata/conformance_vectors.json"

type vectorPack struct {
	Keysets map[string]json.RawMessage `json:"keysets"`
	Vectors []struct {
		ID      string `json:"id"`
		Desc    string `json:"desc"`
		Keyset  string `json:"keyset"`
		NowUnix int64  `json:"now_unix"`
		Token   string `json:"token"`
		Expect  struct {
			Verdict      string            `json:"verdict"`
			Reason       string            `json:"reason"`
			GraceState   string            `json:"grace_state"`
			InternalTier string            `json:"internal_tier"`
			Entitlements map[string]string `json:"entitlements"`
		} `json:"expect"`
	} `json:"vectors"`
}

func loadPack(t *testing.T) vectorPack {
	t.Helper()
	raw, err := os.ReadFile(conformanceFile)
	if err != nil {
		t.Fatalf("read %s: %v", conformanceFile, err)
	}
	var pack vectorPack
	if err := json.Unmarshal(raw, &pack); err != nil {
		t.Fatalf("unmarshal vector pack: %v", err)
	}
	return pack
}

// TestConformanceVectors runs every Pharlux conformance vector under
// PharluxPolicy and asserts the exact expected verdict.
func TestConformanceVectors(t *testing.T) {
	pack := loadPack(t)
	keysets := make(map[string]*KeySet, len(pack.Keysets))
	for name, raw := range pack.Keysets {
		ks, err := ParseJWKS(raw)
		if err != nil {
			t.Fatalf("parse keyset %q: %v", name, err)
		}
		keysets[name] = ks
	}

	policy := PharluxPolicy()
	for _, v := range pack.Vectors {
		t.Run(v.ID, func(t *testing.T) {
			ks, ok := keysets[v.Keyset]
			if !ok {
				t.Fatalf("vector references unknown keyset %q", v.Keyset)
			}
			got := Verify(v.Token, ks, time.Unix(v.NowUnix, 0), policy)

			switch v.Expect.Verdict {
			case "REJECT":
				if got.Accepted {
					t.Fatalf("expected REJECT (%s), got ACCEPT %+v", v.Expect.Reason, got)
				}
				if got.Reason != v.Expect.Reason {
					t.Fatalf("reason: got %q, want %q", got.Reason, v.Expect.Reason)
				}
			case "ACCEPT":
				if !got.Accepted {
					t.Fatalf("expected ACCEPT, got REJECT %q", got.Reason)
				}
				if string(got.GraceState) != v.Expect.GraceState {
					t.Fatalf("grace_state: got %q, want %q", got.GraceState, v.Expect.GraceState)
				}
				if got.InternalTier != v.Expect.InternalTier {
					t.Fatalf("internal_tier: got %q, want %q", got.InternalTier, v.Expect.InternalTier)
				}
				if !reflect.DeepEqual(got.Entitlements, v.Expect.Entitlements) {
					t.Fatalf("entitlements:\n got  %v\n want %v", got.Entitlements, v.Expect.Entitlements)
				}
			default:
				t.Fatalf("unknown expected verdict %q", v.Expect.Verdict)
			}
		})
	}
}

// --- Pre-signature header checks -------------------------------------------
//
// These cases reject BEFORE signature verification, so they can be exercised
// now with arbitrary signatures (no need for the issuer-minted negative
// vectors, which reject only after a valid signature). They cover the
// most security-load-bearing part of the verifier: the fail-closed header
// handling that closes the JWS algorithm-confusion and key-confusion classes.

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// craftToken builds a syntactically valid 3-part token with the given header
// JSON and an arbitrary payload/signature (never a real signature).
func craftToken(headerJSON string) string {
	payload := b64(`{"iss":"validonx"}`)
	sig := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature-but-64bytes-padding-padding-padding-padxxxx"))
	return b64(headerJSON) + "." + payload + "." + sig
}

func TestRejectsNonEdDSAAlg(t *testing.T) {
	ks := mustSandbox(t)
	for _, alg := range []string{"none", "HS256", "RS256", ""} {
		got := Verify(craftToken(`{"alg":"`+alg+`","typ":"JWT","kid":"validonx-sandbox-2026-06"}`), ks, time.Unix(1781090747, 0), PharluxPolicy())
		if got.Accepted || got.Reason != "algorithm not allowed" {
			t.Fatalf("alg=%q: got %+v, want REJECT algorithm not allowed", alg, got)
		}
	}
}

func TestRejectsMissingKid(t *testing.T) {
	ks := mustSandbox(t)
	got := Verify(craftToken(`{"alg":"EdDSA","typ":"JWT"}`), ks, time.Unix(1781090747, 0), PharluxPolicy())
	if got.Accepted || got.Reason != "MissingKid" {
		t.Fatalf("got %+v, want REJECT MissingKid", got)
	}
}

func TestRejectsMalformed(t *testing.T) {
	ks := mustSandbox(t)
	for _, tok := range []string{"", "onlyonepart", "two.parts", "a.b.c.d"} {
		got := Verify(tok, ks, time.Unix(1781090747, 0), PharluxPolicy())
		if got.Accepted || got.Reason != "malformed" {
			t.Fatalf("token %q: got %+v, want REJECT malformed", tok, got)
		}
	}
}

func TestRejectsMisconfigured(t *testing.T) {
	// nil keyset
	if got := Verify("a.b.c", nil, time.Unix(1781090747, 0), PharluxPolicy()); got.Accepted || got.Reason != "misconfigured verifier" {
		t.Fatalf("nil keyset: got %+v, want REJECT misconfigured verifier", got)
	}
	// policy with no MapTier
	if got := Verify("a.b.c", mustSandbox(t), time.Unix(1781090747, 0), Policy{Audience: "pharlux"}); got.Accepted || got.Reason != "misconfigured verifier" {
		t.Fatalf("nil MapTier: got %+v, want REJECT misconfigured verifier", got)
	}
}

func mustSandbox(t *testing.T) *KeySet {
	t.Helper()
	pack := loadPack(t)
	ks, err := ParseJWKS(pack.Keysets["sandbox"])
	if err != nil {
		t.Fatalf("parse sandbox keyset: %v", err)
	}
	return ks
}
