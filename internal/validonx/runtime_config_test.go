package validonx

import (
	"context"
	"strings"
	"testing"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/secretcrypto"
)

// F-R2: an install configured with a service_key but no explicit base_url must
// resolve against ValidonX's DefaultBaseURL, not silently drop to Free. The
// previous guard ordered the IsConfigured() check (which itself requires a
// non-empty BaseURL) before the fallback, making the fallback dead code — a
// paying service_key-only customer lost their Pro/Enterprise entitlement.
func TestLoadRuntimeConfigServiceKeyOnlyGetsDefaultBaseURL(t *testing.T) {
	// db=nil → secrets.yaml-only path (no DB row).
	cfg, err := LoadRuntimeConfig(context.Background(), nil, &config.ValidonXSecrets{
		ServiceKey: "svc_live_abc123",
	}, nil)
	if err != nil {
		t.Fatalf("LoadRuntimeConfig: %v", err)
	}
	if cfg.BaseURL != DefaultBaseURL {
		t.Errorf("service_key-only install BaseURL = %q, want DefaultBaseURL %q", cfg.BaseURL, DefaultBaseURL)
	}
	if !cfg.IsConfigured() {
		t.Error("service_key-only install should be Configured (non-Free) once the default base_url is applied")
	}
}

// An explicit base_url is never overridden by the default fallback.
func TestLoadRuntimeConfigExplicitBaseURLPreserved(t *testing.T) {
	cfg, err := LoadRuntimeConfig(context.Background(), nil, &config.ValidonXSecrets{
		ServiceKey: "svc_live_abc123",
		BaseURL:    "https://validonx.example.test",
	}, nil)
	if err != nil {
		t.Fatalf("LoadRuntimeConfig: %v", err)
	}
	if cfg.BaseURL != "https://validonx.example.test" {
		t.Errorf("explicit BaseURL overwritten: got %q", cfg.BaseURL)
	}
}

// A wholly empty config stays Free (no service_key → no default base_url, not
// Configured). The fallback must not manufacture a licensed-looking config.
func TestLoadRuntimeConfigEmptyStaysFree(t *testing.T) {
	cfg, err := LoadRuntimeConfig(context.Background(), nil, &config.ValidonXSecrets{}, nil)
	if err != nil {
		t.Fatalf("LoadRuntimeConfig: %v", err)
	}
	if cfg.BaseURL != "" {
		t.Errorf("empty config should not get a base_url, got %q", cfg.BaseURL)
	}
	if cfg.IsConfigured() {
		t.Error("empty config must not be Configured (should be Free)")
	}
}

// VX-CFG-1: a non-empty credential round-trips through encrypt/decrypt and the
// stored form is real ciphertext (enc:v1: prefixed, plaintext not embedded).
func TestConfigFieldEncryptRoundTrip(t *testing.T) {
	key := secretcrypto.DeriveKey([]byte("install-master"), ConfigEncKeyLabel)
	const secret = "svc_live_9f86d081884c7d659a2feaa0c55ad015"

	enc, err := encryptField(key, secret)
	if err != nil {
		t.Fatalf("encryptField: %v", err)
	}
	if !secretcrypto.IsEncrypted(enc) {
		t.Fatalf("encrypted value missing enc:v1: prefix: %q", enc)
	}
	if strings.Contains(enc, secret) {
		t.Fatal("ciphertext leaks the plaintext credential")
	}

	got, err := decryptField(key, enc)
	if err != nil {
		t.Fatalf("decryptField: %v", err)
	}
	if got != secret {
		t.Fatalf("round trip = %q, want %q", got, secret)
	}
}

// VX-CFG-1: an empty credential must stay the empty string through both
// helpers, or the "empty string clears the field" upsert/merge semantics break
// (Encrypt("") would otherwise yield a non-empty ciphertext).
func TestConfigFieldEmptyStaysEmpty(t *testing.T) {
	key := secretcrypto.DeriveKey([]byte("install-master"), ConfigEncKeyLabel)

	enc, err := encryptField(key, "")
	if err != nil {
		t.Fatalf("encryptField(\"\"): %v", err)
	}
	if enc != "" {
		t.Fatalf("encryptField(\"\") = %q, want empty", enc)
	}
	dec, err := decryptField(key, "")
	if err != nil {
		t.Fatalf("decryptField(\"\"): %v", err)
	}
	if dec != "" {
		t.Fatalf("decryptField(\"\") = %q, want empty", dec)
	}
}

// VX-CFG-1: decryptField passes through legacy plaintext (a value written
// before encryption at rest landed) unchanged — this is what keeps a
// not-yet-migrated row readable, and works even with a nil key.
func TestConfigFieldDecryptLegacyPlaintextPassthrough(t *testing.T) {
	const legacy = "svc_live_not_yet_encrypted"
	if secretcrypto.IsEncrypted(legacy) {
		t.Fatal("legacy plaintext should not look encrypted")
	}
	got, err := decryptField(nil, legacy)
	if err != nil {
		t.Fatalf("decryptField(nil, legacy): %v", err)
	}
	if got != legacy {
		t.Fatalf("legacy passthrough = %q, want %q", got, legacy)
	}
}

// VX-CFG-1: the startup migration's core is planConfigEncryption — legacy
// plaintext gets encrypted in place, and a second pass over the now-encrypted
// values is a no-op (migrated=0). This is the idempotence guarantee that lets
// EncryptLegacyValidonXConfig run safely on every boot, unit-tested without a
// Postgres harness (Copilot #3).
func TestPlanConfigEncryptionMigratesAndIsIdempotent(t *testing.T) {
	key := secretcrypto.DeriveKey([]byte("install-master"), ConfigEncKeyLabel)
	const (
		svc = "svc_live_partner_key"
		lic = "VLDX-license-string"
	)

	// First pass: both legacy plaintext fields get encrypted.
	encSvc, encLic, migrated, err := planConfigEncryption(key, svc, lic)
	if err != nil {
		t.Fatalf("plan pass 1: %v", err)
	}
	if migrated != 2 {
		t.Fatalf("pass 1 migrated = %d, want 2", migrated)
	}
	if !secretcrypto.IsEncrypted(encSvc) || !secretcrypto.IsEncrypted(encLic) {
		t.Fatal("pass 1 did not encrypt both fields")
	}
	// The stored ciphertext must decrypt back to the originals.
	if got, _ := decryptField(key, encSvc); got != svc {
		t.Fatalf("service_key round trip = %q, want %q", got, svc)
	}
	if got, _ := decryptField(key, encLic); got != lic {
		t.Fatalf("license_key round trip = %q, want %q", got, lic)
	}

	// Second pass over the already-encrypted values: no-op.
	sameSvc, sameLic, migrated2, err := planConfigEncryption(key, encSvc, encLic)
	if err != nil {
		t.Fatalf("plan pass 2: %v", err)
	}
	if migrated2 != 0 {
		t.Fatalf("pass 2 migrated = %d, want 0 (idempotent)", migrated2)
	}
	if sameSvc != encSvc || sameLic != encLic {
		t.Fatal("pass 2 mutated already-encrypted values")
	}
}

// A row with one already-encrypted field and one legacy field migrates only
// the legacy field (migrated=1), and an empty field is left untouched.
func TestPlanConfigEncryptionMixedAndEmpty(t *testing.T) {
	key := secretcrypto.DeriveKey([]byte("install-master"), ConfigEncKeyLabel)

	preEnc, err := secretcrypto.Encrypt(key, "already_encrypted_service_key")
	if err != nil {
		t.Fatalf("seed encrypt: %v", err)
	}

	// service_key already encrypted, license_key empty → nothing to do.
	newSvc, newLic, migrated, err := planConfigEncryption(key, preEnc, "")
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if migrated != 0 {
		t.Fatalf("migrated = %d, want 0 (encrypted + empty)", migrated)
	}
	if newSvc != preEnc || newLic != "" {
		t.Fatalf("values mutated: svc=%q lic=%q", newSvc, newLic)
	}

	// service_key already encrypted, license_key legacy → migrate just the one.
	_, newLic2, migrated2, err := planConfigEncryption(key, preEnc, "VLDX-legacy")
	if err != nil {
		t.Fatalf("plan mixed: %v", err)
	}
	if migrated2 != 1 {
		t.Fatalf("mixed migrated = %d, want 1", migrated2)
	}
	if !secretcrypto.IsEncrypted(newLic2) {
		t.Fatal("legacy license_key was not encrypted")
	}
}
