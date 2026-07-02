package releasesign

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestVerifyWithKey(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("vectis-linux-amd64 bytes")
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))

	if err := VerifyWithKey(pub, data, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}

	// Tampered payload must fail.
	if err := VerifyWithKey(pub, []byte("tampered"), sig); err == nil {
		t.Error("tampered data accepted")
	}
	// Wrong key must fail.
	otherPub, _, _ := ed25519.GenerateKey(nil)
	if err := VerifyWithKey(otherPub, data, sig); err == nil {
		t.Error("signature accepted under wrong key")
	}
	// Malformed signature must fail, not panic.
	if err := VerifyWithKey(pub, data, "not-base64!!"); err == nil {
		t.Error("malformed base64 signature accepted")
	}
	if err := VerifyWithKey(pub, data, base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Error("wrong-length signature accepted")
	}
}

// Verify must fail closed when no key is embedded (the default build state until
// the release keypair is generated).
func TestVerifyFailsClosedWhenUnconfigured(t *testing.T) {
	restore := SetSigningKeyForTest(nil)
	defer restore()

	if Configured() {
		t.Fatal("expected unconfigured")
	}
	if err := Verify([]byte("x"), "sig"); err != ErrNotConfigured {
		t.Fatalf("want ErrNotConfigured, got %v", err)
	}
}

// Verify uses the embedded (test-injected) key end to end.
func TestVerifyUsesEmbeddedKey(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	restore := SetSigningKeyForTest(pub)
	defer restore()

	data := []byte("releases-stable.json contents")
	good := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, data))
	if err := Verify(data, good); err != nil {
		t.Fatalf("embedded-key verify failed: %v", err)
	}
	if err := Verify([]byte("forged manifest"), good); err == nil {
		t.Error("forged manifest accepted")
	}
}
