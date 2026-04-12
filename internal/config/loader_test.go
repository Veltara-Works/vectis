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
