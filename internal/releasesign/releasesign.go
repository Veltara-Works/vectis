// Package releasesign verifies Ed25519 signatures over Vectis release artifacts
// (the host CLI binary and the release-channel manifests) using a public key
// compiled into the binary. It closes the supply-chain gap where a compromise
// of the download origin/CDN (dl.vectismail.com R2, DNS, or a TLS-strip MITM)
// could serve a malicious binary or manifest that a same-origin SHA256 check
// cannot detect (audit E-H2/E-H3).
//
// The trust root is a single Ed25519 public key baked in at build time. The
// matching PRIVATE key exists only as the VECTIS_RELEASE_SIGNING_KEY GitHub
// Actions secret used by .github/workflows/release.yml — it never lives in the
// repo, an image, or a running install. An attacker who controls the download
// origin still cannot forge a signature without that offline key.
//
// Verification is pure crypto/ed25519 (stdlib) — no runtime cosign binary and
// no third-party dependency.
package releasesign

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// PublicKeyB64 is the standard-base64 encoding of the 32-byte Ed25519 public
// key that signs Vectis release artifacts. It is EMPTY until the release keypair
// is generated for v0.1.39 (`go run ./cmd/release-sign -genkey`) and the public
// half is pasted here. While empty, Verify fails closed (ErrNotConfigured) so a
// binary built without the key can never silently accept an unsigned artifact.
const PublicKeyB64 = ""

// ErrNotConfigured means this build has no embedded release public key, so no
// signature can be trusted. Callers that gate an install/update on Verify must
// treat this as a hard failure, not a skip.
var ErrNotConfigured = errors.New("release signing public key not embedded in this build")

// signingPublicKey is the parsed embedded key (nil when PublicKeyB64 is empty).
// It is a package var rather than a hard constant so tests — in this and in
// consuming packages, via SetSigningKeyForTest — can exercise the verify paths
// with an ephemeral key.
var signingPublicKey = mustParseEmbeddedKey()

func mustParseEmbeddedKey() ed25519.PublicKey {
	if PublicKeyB64 == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(PublicKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		// A malformed embedded key is a build-time mistake; refuse to run with a
		// half-configured trust root rather than silently disabling verification.
		panic(fmt.Sprintf("releasesign: invalid embedded PublicKeyB64: err=%v len=%d", err, len(raw)))
	}
	return ed25519.PublicKey(raw)
}

// Configured reports whether this build has an embedded release public key.
func Configured() bool { return signingPublicKey != nil }

// Verify checks that sigB64 (standard-base64 of a 64-byte Ed25519 signature) is
// a valid signature over data under the embedded release public key. It returns
// ErrNotConfigured when no key is embedded, and a non-nil error on any decode or
// verification failure. A nil return means the artifact is authentic.
func Verify(data []byte, sigB64 string) error {
	if signingPublicKey == nil {
		return ErrNotConfigured
	}
	return VerifyWithKey(signingPublicKey, data, sigB64)
}

// VerifyWithKey is the key-injected core of Verify, exported for tests.
func VerifyWithKey(pub ed25519.PublicKey, data []byte, sigB64 string) error {
	if len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("release public key wrong size: %d", len(pub))
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(sigB64))
	if err != nil {
		return fmt.Errorf("decode release signature: %w", err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("release signature wrong size: %d (want %d)", len(sig), ed25519.SignatureSize)
	}
	if !ed25519.Verify(pub, data, sig) {
		return errors.New("release signature verification failed")
	}
	return nil
}

// SetSigningKeyForTest overrides the embedded key for the duration of a test and
// returns a function that restores the previous value. It is intended only for
// tests (in this and consuming packages) — production code relies on the
// compiled-in PublicKeyB64.
func SetSigningKeyForTest(pub ed25519.PublicKey) func() {
	prev := signingPublicKey
	signingPublicKey = pub
	return func() { signingPublicKey = prev }
}
