package config

// ---------------------------------------------------------------------------
// VectisConfig — maps to config.yaml ("what the system is")
// ---------------------------------------------------------------------------

// VectisConfig is the top-level configuration loaded from config.yaml.
type VectisConfig struct {
	Hostname     string              `yaml:"hostname"`
	TLS          TLSConfig           `yaml:"tls"`
	Resources    ResourceConfig      `yaml:"resources"`
	ClamAV       ClamAVConfig        `yaml:"clamav"`
	Rspamd       RspamdConfig        `yaml:"rspamd"`
	Postfix      PostfixConfig       `yaml:"postfix"`
	Dovecot      DovecotConfig       `yaml:"dovecot"`
	Backup       BackupConfig        `yaml:"backup"`
	Logging      LoggingConfig       `yaml:"logging"`
	Admin        AdminConfig         `yaml:"admin"`
	Orchestrator OrchestratorConfig  `yaml:"orchestrator"`
	Alerts       AlertsConfig        `yaml:"alerts"`
}

// TLSConfig controls certificate provisioning.
// Provider is "letsencrypt" or "custom".  When "custom", CertPath and KeyPath
// must point to PEM files on disk.
type TLSConfig struct {
	Provider string `yaml:"provider"` // "letsencrypt" | "custom"
	Email    string `yaml:"email"`    // ACME account email (letsencrypt)
	CertPath string `yaml:"cert_path,omitempty"` // PEM certificate  (custom)
	KeyPath  string `yaml:"key_path,omitempty"`  // PEM private key  (custom)
}

// ResourceConfig selects a resource-limit profile that governs container
// memory and CPU constraints.
type ResourceConfig struct {
	Profile string `yaml:"profile"` // "dev" | "small" | "production" | "enterprise"
}

// ClamAVConfig controls the ClamAV antivirus sidecar.
// Setting Profile to "none" omits the container entirely.
type ClamAVConfig struct {
	Profile string `yaml:"profile"` // "none" | "dev" | "small" | "production" | "enterprise"
}

// RspamdConfig tunes the Rspamd spam-filtering thresholds.
type RspamdConfig struct {
	SpamThreshold   float64 `yaml:"spam_threshold"`   // default 15.0
	RejectThreshold float64 `yaml:"reject_threshold"` // default 999 (effectively disabled)
	GreylistEnabled bool    `yaml:"greylist_enabled"`
}

// PostfixConfig holds Postfix MTA knobs.
type PostfixConfig struct {
	MessageSizeLimit int    `yaml:"message_size_limit"` // bytes; default 52428800 (50 MB)
	SmtpBanner       string `yaml:"smtp_banner"`
}

// DovecotConfig holds Dovecot IMAP/LDA knobs.
type DovecotConfig struct {
	MailLocation   string `yaml:"mail_location"`    // default "maildir:/var/vectis/mail/%d/%n/Maildir"
	QuotaDefaultMB int    `yaml:"quota_default_mb"` // default 1024
}

// BackupConfig controls periodic backup behaviour.
type BackupConfig struct {
	Enabled    bool   `yaml:"enabled"`
	Schedule   string `yaml:"schedule"`    // cron expression, e.g. "0 3 * * *"
	RetainDays int    `yaml:"retain_days"`
}

// LoggingConfig sets the logging driver and rotation policy for containers.
type LoggingConfig struct {
	Level    string `yaml:"level"`      // "debug" | "info" | "warn" | "error"
	Driver   string `yaml:"driver"`     // Docker log driver, e.g. "json-file"
	MaxSizeMB int   `yaml:"max_size_mb"`
	MaxFiles  int   `yaml:"max_files"`
}

// AdminConfig governs the administrative HTTP interface.
type AdminConfig struct {
	ListenAddr      string `yaml:"listen_addr"`      // default ":8080"
	SessionTTLHours int    `yaml:"session_ttl_hours"` // default 24
}

// OrchestratorConfig controls the update orchestrator timeouts and behaviour.
type OrchestratorConfig struct {
	ImagePullTimeout   int `yaml:"image_pull_timeout"`   // seconds, default 300
	HealthCheckTimeout int `yaml:"health_check_timeout"` // seconds per service, default 120
	DBMigrationTimeout int `yaml:"db_migration_timeout"` // seconds, default 60
	ApplyTimeout       int `yaml:"apply_timeout"`        // seconds total, default 600
}

// AlertsConfig controls alerting for service failures and critical events.
type AlertsConfig struct {
	Email   AlertEmailConfig   `yaml:"email"`
	Webhook AlertWebhookConfig `yaml:"webhook"`
}

// AlertEmailConfig configures email-based alerts.
type AlertEmailConfig struct {
	Enabled    bool     `yaml:"enabled"`
	Recipients []string `yaml:"recipients"`
}

// AlertWebhookConfig configures webhook-based alerts.
type AlertWebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

// ---------------------------------------------------------------------------
// VectisSecrets — maps to secrets.yaml ("what must never hit git")
// ---------------------------------------------------------------------------

// VectisSecrets is the top-level secrets structure loaded from secrets.yaml.
type VectisSecrets struct {
	Database     DatabaseSecrets      `yaml:"database"`
	Valkey       ValkeySecrets        `yaml:"valkey"`
	API          APISecrets           `yaml:"api"`
	Orchestrator OrchestratorSecrets  `yaml:"orchestrator"`
	DKIM         DKIMSecrets          `yaml:"dkim"`
	Cloudflare   *CloudflareSecrets   `yaml:"cloudflare,omitempty"`
}

// DatabaseSecrets holds connection details and per-service credentials for
// the PostgreSQL database (three DB users per ADR-019).
type DatabaseSecrets struct {
	Host            string `yaml:"host"`
	Port            int    `yaml:"port"`
	Name            string `yaml:"name"`
	APIUser         string `yaml:"api_user"`
	APIPassword     string `yaml:"api_password"`
	PostfixUser     string `yaml:"postfix_user"`
	PostfixPassword string `yaml:"postfix_password"`
	DovecotUser     string `yaml:"dovecot_user"`
	DovecotPassword string `yaml:"dovecot_password"`
}

// ValkeySecrets holds connection details for the Valkey (Redis-compatible)
// key-value store.
type ValkeySecrets struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Password string `yaml:"password"`
}

// APISecrets holds the cookie-signing secret and the initial admin account
// credentials seeded by the installer.
type APISecrets struct {
	Secret        string `yaml:"secret"`         // cookie / JWT signing key
	AdminEmail    string `yaml:"admin_email"`    // initial admin, used by installer only
	AdminPassword string `yaml:"admin_password"` // initial admin, used by installer only
}

// OrchestratorSecrets holds the bearer token used for internal HTTP calls
// between the API server and the orchestrator.
type OrchestratorSecrets struct {
	Token string `yaml:"token"`
}

// DKIMSecrets stores the base path where per-domain DKIM private keys live.
type DKIMSecrets struct {
	KeyBasePath string `yaml:"key_base_path"` // default "/var/vectis/dkim"
}

// CloudflareSecrets is optional and supplies the API token used by acme.sh
// for DNS-01 challenges.
type CloudflareSecrets struct {
	APIToken string `yaml:"api_token"`
}
