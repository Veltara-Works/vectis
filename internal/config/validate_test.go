package config

import (
	"testing"
)

func validConfig() *VectisConfig {
	return &VectisConfig{
		Hostname:  "mail.example.com",
		TLS:       TLSConfig{Provider: "letsencrypt", Email: "admin@example.com"},
		Resources: ResourceConfig{Profile: "production"},
		ClamAV:    ClamAVConfig{Profile: "production"},
		Rspamd:    RspamdConfig{SpamThreshold: 15},
		Postfix:   PostfixConfig{MessageSizeLimit: 52428800},
		Dovecot:   DovecotConfig{QuotaDefaultMB: 1024},
		Logging:   LoggingConfig{Level: "info"},
		Admin:     AdminConfig{ListenAddr: ":8080", SessionTTLHours: 24},
	}
}

func validSecrets() *VectisSecrets {
	return &VectisSecrets{
		Database: DatabaseSecrets{
			SuperuserPassword: "superpass",
			APIPassword:       "apipass",
			PostfixPassword:   "pfpass",
			DovecotPassword:   "dcpass",
			Name:              "vectis",
		},
		Valkey:       ValkeySecrets{Password: "vkpass"},
		API:          APISecrets{Secret: "12345678901234567890123456789012", AdminEmail: "admin@example.com", AdminPassword: "securepass", BackupEncryptionKey: "0123456789abcdef0123456789abcdef"},
		Orchestrator: OrchestratorSecrets{Token: "orchtoken"},
	}
}

func TestValidateConfig_Valid(t *testing.T) {
	r := ValidateConfig(validConfig())
	if !r.IsValid() {
		for _, e := range r.Errors {
			t.Errorf("unexpected error: %s: %s", e.Field, e.Message)
		}
	}
}

func TestValidateConfig_EmptyHostname(t *testing.T) {
	cfg := validConfig()
	cfg.Hostname = ""
	r := ValidateConfig(cfg)
	if r.IsValid() {
		t.Fatal("expected validation error for empty hostname")
	}
	assertHasError(t, r, "hostname")
}

func TestValidateConfig_InvalidHostname(t *testing.T) {
	cfg := validConfig()
	cfg.Hostname = "not a valid hostname!"
	r := ValidateConfig(cfg)
	assertHasError(t, r, "hostname")
}

func TestValidateConfig_TLSProviderInvalid(t *testing.T) {
	cfg := validConfig()
	cfg.TLS.Provider = "selfsigned"
	r := ValidateConfig(cfg)
	assertHasError(t, r, "tls.provider")
}

func TestValidateConfig_TLSEmailRequiredForLetsEncrypt(t *testing.T) {
	cfg := validConfig()
	cfg.TLS.Provider = "letsencrypt"
	cfg.TLS.Email = ""
	r := ValidateConfig(cfg)
	assertHasError(t, r, "tls.email")
}

func TestValidateConfig_TLSEmailNotRequiredForCustom(t *testing.T) {
	cfg := validConfig()
	cfg.TLS.Provider = "custom"
	cfg.TLS.Email = ""
	r := ValidateConfig(cfg)
	assertNoError(t, r, "tls.email")
}

func TestValidateConfig_ResourceProfileInvalid(t *testing.T) {
	cfg := validConfig()
	cfg.Resources.Profile = "huge"
	r := ValidateConfig(cfg)
	assertHasError(t, r, "resources.profile")
}

func TestValidateConfig_ClamAVProfileInvalid(t *testing.T) {
	cfg := validConfig()
	cfg.ClamAV.Profile = "turbo"
	r := ValidateConfig(cfg)
	assertHasError(t, r, "clamav.profile")
}

func TestValidateConfig_SpamThresholdZero(t *testing.T) {
	cfg := validConfig()
	cfg.Rspamd.SpamThreshold = 0
	r := ValidateConfig(cfg)
	assertHasError(t, r, "rspamd.spam_threshold")
}

func TestValidateConfig_MessageSizeLimits(t *testing.T) {
	cfg := validConfig()

	cfg.Postfix.MessageSizeLimit = 0
	r := ValidateConfig(cfg)
	assertHasError(t, r, "postfix.message_size_limit")

	cfg.Postfix.MessageSizeLimit = 200_000_000
	r = ValidateConfig(cfg)
	assertHasError(t, r, "postfix.message_size_limit")
}

func TestValidateConfig_LoggingLevelInvalid(t *testing.T) {
	cfg := validConfig()
	cfg.Logging.Level = "trace"
	r := ValidateConfig(cfg)
	assertHasError(t, r, "logging.level")
}

func TestValidateConfig_AdminListenAddrEmpty(t *testing.T) {
	cfg := validConfig()
	cfg.Admin.ListenAddr = ""
	r := ValidateConfig(cfg)
	assertHasError(t, r, "admin.listen_addr")
}

func TestValidateConfig_SessionTTLZero(t *testing.T) {
	cfg := validConfig()
	cfg.Admin.SessionTTLHours = 0
	r := ValidateConfig(cfg)
	assertHasError(t, r, "admin.session_ttl_hours")
}

func TestValidateSecrets_Valid(t *testing.T) {
	r := ValidateSecrets(validSecrets())
	if !r.IsValid() {
		for _, e := range r.Errors {
			t.Errorf("unexpected error: %s: %s", e.Field, e.Message)
		}
	}
}

func TestValidateSecrets_MissingPasswords(t *testing.T) {
	s := validSecrets()
	s.Database.APIPassword = ""
	s.Database.PostfixPassword = ""
	s.Database.DovecotPassword = ""
	r := ValidateSecrets(s)
	assertHasError(t, r, "database.api_password")
	assertHasError(t, r, "database.postfix_password")
	assertHasError(t, r, "database.dovecot_password")
}

func TestValidateSecrets_ShortAPISecret(t *testing.T) {
	s := validSecrets()
	s.API.Secret = "tooshort"
	r := ValidateSecrets(s)
	assertHasError(t, r, "api.secret")
}

func TestValidateSecrets_ShortAdminPassword(t *testing.T) {
	s := validSecrets()
	s.API.AdminPassword = "short"
	r := ValidateSecrets(s)
	assertHasError(t, r, "api.admin_password")
}

func TestValidateSecrets_BackupKeyRequired(t *testing.T) {
	s := validSecrets()
	s.API.BackupEncryptionKey = ""
	r := ValidateSecrets(s)
	if r.IsValid() {
		t.Fatal("missing backup encryption key should be a validation error")
	}
	assertHasError(t, r, "api.backup_encryption_key")
}

func TestValidateSecrets_BackupKeyNoWarningWhenSet(t *testing.T) {
	s := validSecrets()
	s.API.BackupEncryptionKey = "0123456789abcdef0123456789abcdef"
	r := ValidateSecrets(s)
	for _, w := range r.Warnings {
		if w.Field == "api.backup_encryption_key" {
			t.Error("should not warn when backup encryption key is set")
		}
	}
}

func TestValidonXConfigured(t *testing.T) {
	s := &VectisSecrets{}
	if s.ValidonXConfigured() {
		t.Error("nil ValidonX should return false")
	}

	s.ValidonX = &ValidonXSecrets{}
	if s.ValidonXConfigured() {
		t.Error("empty ValidonX should return false")
	}

	s.ValidonX = &ValidonXSecrets{BaseURL: "https://api.validonx.com", ServiceKey: "key"}
	if !s.ValidonXConfigured() {
		t.Error("populated ValidonX should return true")
	}
}

func assertHasError(t *testing.T, r *ValidationResult, field string) {
	t.Helper()
	for _, e := range r.Errors {
		if e.Field == field {
			return
		}
	}
	t.Errorf("expected validation error for field %q", field)
}

func assertNoError(t *testing.T, r *ValidationResult, field string) {
	t.Helper()
	for _, e := range r.Errors {
		if e.Field == field {
			t.Errorf("unexpected validation error for field %q: %s", field, e.Message)
		}
	}
}
