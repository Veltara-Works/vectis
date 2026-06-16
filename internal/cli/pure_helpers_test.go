package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/config"
)

// validConfig returns a VectisConfig that validateConfig accepts with zero
// errors. Tests mutate a single field to assert the corresponding rule fires.
func validConfig() config.VectisConfig {
	return config.VectisConfig{
		Hostname:  "mail.example.com",
		TLS:       config.TLSConfig{Provider: "letsencrypt", Email: "admin@example.com"},
		Resources: config.ResourceConfig{Profile: "small"},
		ClamAV:    config.ClamAVConfig{Profile: "none"},
		Rspamd:    config.RspamdConfig{SpamThreshold: 15, RejectThreshold: 999},
		Postfix:   config.PostfixConfig{MessageSizeLimit: 52428800},
		Dovecot:   config.DovecotConfig{MailLocation: "maildir:/var/vectis/mail", QuotaDefaultMB: 1024},
		Backup:    config.BackupConfig{Enabled: false},
		Logging:   config.LoggingConfig{Level: "info"},
		Admin:     config.AdminConfig{ListenAddr: ":8080", SessionTTLHours: 24},
	}
}

// validSecrets returns a VectisSecrets that validateSecrets accepts with zero
// errors.
func validSecrets() config.VectisSecrets {
	return config.VectisSecrets{
		Database: config.DatabaseSecrets{
			Host: "vectis-postgres", Port: 5432, Name: "vectis",
			APIUser: "vectis_api", APIPassword: "x",
			PostfixUser: "vectis_postfix", PostfixPassword: "x",
			DovecotUser: "vectis_dovecot", DovecotPassword: "x",
		},
		Valkey:       config.ValkeySecrets{Host: "vectis-valkey", Port: 6379, Password: "x"},
		API:          config.APISecrets{Secret: strings.Repeat("a", 32), AdminEmail: "admin@example.com", AdminPassword: "x"},
		Orchestrator: config.OrchestratorSecrets{Token: "orchestrator-token"},
		DKIM:         config.DKIMSecrets{KeyBasePath: "/var/vectis/dkim"},
	}
}

func hasFieldError(errs []validateError, field string) bool {
	for _, e := range errs {
		if e.Field == field {
			return true
		}
	}
	return false
}

func TestValidateConfig_ValidIsClean(t *testing.T) {
	if errs := validateConfig(ptrConfig(validConfig())); len(errs) != 0 {
		t.Fatalf("validConfig() produced %d errors, want 0: %+v", len(errs), errs)
	}
}

func TestValidateConfig_FieldRules(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*config.VectisConfig)
		wantField string
	}{
		{"empty hostname", func(c *config.VectisConfig) { c.Hostname = "" }, "hostname"},
		{"empty tls provider", func(c *config.VectisConfig) { c.TLS.Provider = "" }, "tls.provider"},
		{"unknown tls provider", func(c *config.VectisConfig) { c.TLS.Provider = "bogus" }, "tls.provider"},
		{"letsencrypt without email", func(c *config.VectisConfig) { c.TLS = config.TLSConfig{Provider: "letsencrypt"} }, "tls.email"},
		{"custom without cert", func(c *config.VectisConfig) { c.TLS = config.TLSConfig{Provider: "custom", KeyPath: "/k"} }, "tls.cert_path"},
		{"custom without key", func(c *config.VectisConfig) { c.TLS = config.TLSConfig{Provider: "custom", CertPath: "/c"} }, "tls.key_path"},
		{"bad resources profile", func(c *config.VectisConfig) { c.Resources.Profile = "huge" }, "resources.profile"},
		{"bad clamav profile", func(c *config.VectisConfig) { c.ClamAV.Profile = "huge" }, "clamav.profile"},
		{"zero spam threshold", func(c *config.VectisConfig) { c.Rspamd.SpamThreshold = 0 }, "rspamd.spam_threshold"},
		{"zero reject threshold", func(c *config.VectisConfig) { c.Rspamd.RejectThreshold = 0 }, "rspamd.reject_threshold"},
		{"zero message size", func(c *config.VectisConfig) { c.Postfix.MessageSizeLimit = 0 }, "postfix.message_size_limit"},
		{"empty mail location", func(c *config.VectisConfig) { c.Dovecot.MailLocation = "" }, "dovecot.mail_location"},
		{"zero quota", func(c *config.VectisConfig) { c.Dovecot.QuotaDefaultMB = 0 }, "dovecot.quota_default_mb"},
		{"backup enabled without schedule", func(c *config.VectisConfig) { c.Backup = config.BackupConfig{Enabled: true} }, "backup.schedule"},
		{"backup negative retain", func(c *config.VectisConfig) {
			c.Backup = config.BackupConfig{Enabled: true, Schedule: "0 3 * * *", RetainDays: -1}
		}, "backup.retain_days"},
		{"backup bad timezone", func(c *config.VectisConfig) { c.Backup.Timezone = "Mars/Olympus" }, "backup.timezone"},
		{"empty logging level", func(c *config.VectisConfig) { c.Logging.Level = "" }, "logging.level"},
		{"unknown logging level", func(c *config.VectisConfig) { c.Logging.Level = "trace" }, "logging.level"},
		{"empty listen addr", func(c *config.VectisConfig) { c.Admin.ListenAddr = "" }, "admin.listen_addr"},
		{"zero session ttl", func(c *config.VectisConfig) { c.Admin.SessionTTLHours = 0 }, "admin.session_ttl_hours"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := validConfig()
			tt.mutate(&cfg)
			errs := validateConfig(&cfg)
			if !hasFieldError(errs, tt.wantField) {
				t.Errorf("expected error on field %q, got %+v", tt.wantField, errs)
			}
		})
	}
}

func TestValidateSecrets_ValidIsClean(t *testing.T) {
	s := validSecrets()
	if errs := validateSecrets(&s); len(errs) != 0 {
		t.Fatalf("validSecrets() produced %d errors, want 0: %+v", len(errs), errs)
	}
}

func TestValidateSecrets_FieldRules(t *testing.T) {
	tests := []struct {
		name      string
		mutate    func(*config.VectisSecrets)
		wantField string
	}{
		{"empty db host", func(s *config.VectisSecrets) { s.Database.Host = "" }, "database.host"},
		{"db port zero", func(s *config.VectisSecrets) { s.Database.Port = 0 }, "database.port"},
		{"db port too high", func(s *config.VectisSecrets) { s.Database.Port = 70000 }, "database.port"},
		{"empty db name", func(s *config.VectisSecrets) { s.Database.Name = "" }, "database.name"},
		{"empty api password", func(s *config.VectisSecrets) { s.Database.APIPassword = "" }, "database.api_password"},
		{"empty dovecot password", func(s *config.VectisSecrets) { s.Database.DovecotPassword = "" }, "database.dovecot_password"},
		{"empty valkey host", func(s *config.VectisSecrets) { s.Valkey.Host = "" }, "valkey.host"},
		{"valkey port zero", func(s *config.VectisSecrets) { s.Valkey.Port = 0 }, "valkey.port"},
		{"empty valkey password", func(s *config.VectisSecrets) { s.Valkey.Password = "" }, "valkey.password"},
		{"empty api secret", func(s *config.VectisSecrets) { s.API.Secret = "" }, "api.secret"},
		{"short api secret", func(s *config.VectisSecrets) { s.API.Secret = "tooshort" }, "api.secret"},
		{"empty admin email", func(s *config.VectisSecrets) { s.API.AdminEmail = "" }, "api.admin_email"},
		{"empty orchestrator token", func(s *config.VectisSecrets) { s.Orchestrator.Token = "" }, "orchestrator.token"},
		{"empty dkim base path", func(s *config.VectisSecrets) { s.DKIM.KeyBasePath = "" }, "dkim.key_base_path"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := validSecrets()
			tt.mutate(&s)
			errs := validateSecrets(&s)
			if !hasFieldError(errs, tt.wantField) {
				t.Errorf("expected error on field %q, got %+v", tt.wantField, errs)
			}
		})
	}
}

func ptrConfig(c config.VectisConfig) *config.VectisConfig { return &c }

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		in   int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{5368709120, "5.0 GB"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := formatBytes(tt.in); got != tt.want {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestFormatUptime(t *testing.T) {
	tests := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"sub-minute", 30 * time.Second, "0m"},
		{"minutes", 45 * time.Minute, "45m"},
		{"hours and minutes", 2*time.Hour + 15*time.Minute, "2h 15m"},
		{"exact hour", time.Hour, "1h 0m"},
		{"days and hours", 3*24*time.Hour + 5*time.Hour, "3d 5h"},
		{"days drop minutes", 24*time.Hour + 90*time.Minute, "1d 1h"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatUptime(tt.d); got != tt.want {
				t.Errorf("formatUptime(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}

func TestParseAdminPassword(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   string
	}{
		{"simple", "admin_password=secret123\n", "secret123"},
		{"among other lines", "foo=bar\nadmin_password=hunter2\nbaz=qux\n", "hunter2"},
		{"trailing whitespace trimmed", "admin_password=  spaced  \n", "spaced"},
		{"absent", "foo=bar\nbaz=qux\n", ""},
		{"empty input", "", ""},
		{"indented key not matched", "  admin_password=nope\n", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseAdminPassword(tt.output); got != tt.want {
				t.Errorf("parseAdminPassword(%q) = %q, want %q", tt.output, got, tt.want)
			}
		})
	}
}
