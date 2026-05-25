package config

import (
	"os"
	"path/filepath"
	"testing"
)

const testConfigYAML = `hostname: mail.test.com
tls:
  provider: letsencrypt
  email: admin@test.com
resources:
  profile: dev
clamav:
  profile: none
rspamd:
  spam_threshold: 15
  reject_threshold: 999
postfix:
  message_size_limit: 52428800
  smtp_banner: "$myhostname ESMTP"
dovecot:
  quota_default_mb: 1024
logging:
  level: info
admin:
  listen_addr: ":8080"
  session_ttl_hours: 24
`

const testSecretsYAML = `database:
  host: localhost
  port: 5432
  name: vectis
  api_user: vectis_api
  api_password: apipass
  postfix_user: vectis_postfix
  postfix_password: pfpass
  dovecot_user: vectis_dovecot
  dovecot_password: dcpass
valkey:
  host: localhost
  port: 6379
  password: vkpass
api:
  secret: "12345678901234567890123456789012"
  admin_email: admin@test.com
  admin_password: securepass
orchestrator:
  token: orchtoken
dkim:
  key_base_path: /var/vectis/dkim
`

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(testConfigYAML), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	if cfg.Hostname != "mail.test.com" {
		t.Errorf("hostname = %q, want mail.test.com", cfg.Hostname)
	}
	if cfg.TLS.Provider != "letsencrypt" {
		t.Errorf("tls.provider = %q, want letsencrypt", cfg.TLS.Provider)
	}
	if cfg.Postfix.MessageSizeLimit != 52428800 {
		t.Errorf("message_size_limit = %d, want 52428800", cfg.Postfix.MessageSizeLimit)
	}
	if cfg.Admin.SessionTTLHours != 24 {
		t.Errorf("session_ttl_hours = %d, want 24", cfg.Admin.SessionTTLHours)
	}
}

func TestLoadConfig_NotFound(t *testing.T) {
	_, err := LoadConfig("/nonexistent/config.yaml")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("not: [valid yaml"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for invalid YAML")
	}
}

func TestLoadConfig_UnknownField(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	yaml := testConfigYAML + "unknown_field: true\n"
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := LoadConfig(path)
	if err == nil {
		t.Fatal("expected error for unknown field (strict mode)")
	}
}

func TestLoadSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.yaml")
	if err := os.WriteFile(path, []byte(testSecretsYAML), 0644); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecrets(path)
	if err != nil {
		t.Fatalf("LoadSecrets: %v", err)
	}

	if secrets.Database.Name != "vectis" {
		t.Errorf("database.name = %q, want vectis", secrets.Database.Name)
	}
	if secrets.API.Secret != "12345678901234567890123456789012" {
		t.Error("api.secret mismatch")
	}
	if secrets.Orchestrator.Token != "orchtoken" {
		t.Errorf("orchestrator.token = %q, want orchtoken", secrets.Orchestrator.Token)
	}
}

func TestLoadAll(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(testConfigYAML), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte(testSecretsYAML), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, secrets, err := LoadAll(dir)
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}

	if cfg.Hostname != "mail.test.com" {
		t.Errorf("config hostname = %q", cfg.Hostname)
	}
	if secrets.Database.Name != "vectis" {
		t.Errorf("secrets database name = %q", secrets.Database.Name)
	}
}

func TestLoadAll_MissingConfig(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "secrets.yaml"), []byte(testSecretsYAML), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := LoadAll(dir)
	if err == nil {
		t.Fatal("expected error when config.yaml is missing")
	}
}

// TestLoadSecrets_ValidonXForwardCompat asserts that an unknown field
// nested under the validonx: section does NOT cause a strict-unmarshal
// crash. This prevents the class of incident hit on 2026-05-25 where a
// forward-staged secret (customer_one_key, added before v0.1.14 deploy)
// crashed v0.1.12 binaries on host reboot. The unknown field is captured
// in ValidonXSecrets.Forward so it is not silently dropped — operators
// can observe it via the loaded struct if they need to confirm staging.
func TestLoadSecrets_ValidonXForwardCompat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.yaml")
	yaml := testSecretsYAML + `validonx:
  base_url: https://api.validonx.com
  service_key: svckey
  tenant_id: ""
  subscription_id: ""
  server_id: ""
  license_key: ""
  customer_one_key: vectis_known_key_value
  some_future_v0_1_99_key: "this should not crash the loader"
`
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	secrets, err := LoadSecrets(path)
	if err != nil {
		t.Fatalf("LoadSecrets must tolerate unknown validonx.* fields, got: %v", err)
	}
	if secrets.ValidonX == nil {
		t.Fatal("ValidonX block should be loaded")
	}
	if secrets.ValidonX.CustomerOneKey != "vectis_known_key_value" {
		t.Errorf("known field CustomerOneKey not parsed; got %q", secrets.ValidonX.CustomerOneKey)
	}
	got, ok := secrets.ValidonX.Forward["some_future_v0_1_99_key"]
	if !ok {
		t.Fatal("unknown field should land in Forward map, not be silently dropped")
	}
	if gotStr, _ := got.(string); gotStr != "this should not crash the loader" {
		t.Errorf("Forward[some_future_v0_1_99_key] = %v, want the staged sentinel string", got)
	}
}

// TestLoadSecrets_UnknownTopLevel asserts the inline catch-all on
// ValidonXSecrets does NOT defeat strict mode at the top level — a typo
// in a top-level section name (e.g. "vlidonx:" instead of "validonx:")
// must still fail loudly so operational typos are caught immediately.
func TestLoadSecrets_UnknownTopLevel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.yaml")
	yaml := testSecretsYAML + "vlidonx:\n  base_url: typo\n"
	if err := os.WriteFile(path, []byte(yaml), 0644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadSecrets(path); err == nil {
		t.Fatal("expected strict-mode error for unknown top-level field, got nil")
	}
}
