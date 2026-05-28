package secretcrypto

import (
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := DeriveKey([]byte("master-secret-from-install"), "vectis-webhook-secret-v1")
	plaintext := "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"

	enc, err := Encrypt(key, plaintext)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !IsEncrypted(enc) {
		t.Fatalf("encrypted value missing prefix: %q", enc)
	}
	if strings.Contains(enc, plaintext) {
		t.Fatal("ciphertext leaks plaintext")
	}

	got, err := Decrypt(key, enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if got != plaintext {
		t.Fatalf("round trip = %q, want %q", got, plaintext)
	}
}

func TestDecryptLegacyPlaintextPassthrough(t *testing.T) {
	key := DeriveKey([]byte("master"), "label")
	legacy := "plain-hex-secret-not-yet-encrypted"

	if IsEncrypted(legacy) {
		t.Fatal("legacy value should not look encrypted")
	}
	got, err := Decrypt(key, legacy)
	if err != nil {
		t.Fatalf("decrypt legacy: %v", err)
	}
	if got != legacy {
		t.Fatalf("legacy passthrough = %q, want %q", got, legacy)
	}
}

func TestDecryptWrongKeyFails(t *testing.T) {
	k1 := DeriveKey([]byte("master"), "label")
	k2 := DeriveKey([]byte("different-master"), "label")

	enc, err := Encrypt(k1, "secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if _, err := Decrypt(k2, enc); err == nil {
		t.Fatal("decrypt with wrong key should fail (GCM auth)")
	}
}

func TestDecryptTamperFails(t *testing.T) {
	key := DeriveKey([]byte("master"), "label")
	enc, err := Encrypt(key, "secret")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	// Flip a character in the base64 body.
	body := []byte(enc)
	body[len(body)-1] ^= 0x01
	if _, err := Decrypt(key, string(body)); err == nil {
		t.Fatal("decrypt of tampered ciphertext should fail")
	}
}

func TestDeriveKeyDeterministicAndSeparated(t *testing.T) {
	master := []byte("same-master")
	a1 := DeriveKey(master, "label-a")
	a2 := DeriveKey(master, "label-a")
	b := DeriveKey(master, "label-b")

	if len(a1) != 32 {
		t.Fatalf("key length = %d, want 32", len(a1))
	}
	if string(a1) != string(a2) {
		t.Fatal("same master+label must derive same key")
	}
	if string(a1) == string(b) {
		t.Fatal("different labels must derive different keys")
	}
}
