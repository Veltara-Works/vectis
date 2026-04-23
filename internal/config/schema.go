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
	Audit        AuditConfig         `yaml:"audit"`
	Webmail      WebmailConfig       `yaml:"webmail"`
	Observability ObservabilityConfig `yaml:"observability"`
	RateLimits   RateLimitConfig     `yaml:"rate_limits"`
	Cluster      ClusterConfig       `yaml:"cluster"`
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
	ValkeyHost     string `yaml:"valkey_host"`      // populated from secrets at render time
	ValkeyPort     int    `yaml:"valkey_port"`      // populated from secrets at render time
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
//
// SMTPHost is the "host:port" the alerter dials to submit mail. Empty
// disables email delivery even when Enabled=true — the api container
// has no local SMTP listener and the previous hard-coded `127.0.0.1:25`
// failed silently on every fresh install. Typical values:
//   - "vectis-postfix:25"  — relay via the bundled Postfix (requires
//     postfix's mynetworks to include the vectis-data subnet)
//   - ""                    — disabled; monitor logs a warning once
//
// Recipients may be left empty, in which case the alerter falls back
// to the installer's admin_email so a fresh install doesn't require
// duplicating the address in two files.
type AlertEmailConfig struct {
	Enabled    bool     `yaml:"enabled"`
	SMTPHost   string   `yaml:"smtp_host"`
	Recipients []string `yaml:"recipients"`
}

// AlertWebhookConfig configures webhook-based alerts.
type AlertWebhookConfig struct {
	Enabled bool   `yaml:"enabled"`
	URL     string `yaml:"url"`
}

// AuditConfig controls audit log retention and pruning.
type AuditConfig struct {
	RetentionDays int `yaml:"retention_days"` // entries older than this are pruned; default 90, 0 = no pruning
}

// ObservabilityConfig controls optional Loki + Promtail log aggregation and Grafana.
type ObservabilityConfig struct {
	LokiEnabled     bool `yaml:"loki_enabled"`      // include Loki + Promtail containers; default false
	LokiRetainDays  int  `yaml:"loki_retain_days"`  // log retention in days; default 30
	GrafanaEnabled  bool `yaml:"grafana_enabled"`   // include Grafana container; default false
}

// WebmailConfig controls the optional Roundcube webmail container.
type WebmailConfig struct {
	Enabled    bool   `yaml:"enabled"`               // include webmail container; default false
	UploadMaxMB int   `yaml:"upload_max_mb,omitempty"` // max attachment size in MB; default 25
}

// RateLimitConfig controls Traefik rate limiting middleware for API endpoints.
// Rates are expressed as average requests per second with a burst allowance.
type RateLimitConfig struct {
	AuthAverage   int `yaml:"auth_average"`   // login/logout endpoints, default 10 req/s
	AuthBurst     int `yaml:"auth_burst"`     // burst above average, default 20
	APIAverage    int `yaml:"api_average"`    // general API endpoints, default 50 req/s
	APIBurst      int `yaml:"api_burst"`      // burst above average, default 100
	MutateAverage int `yaml:"mutate_average"` // mutating endpoints (POST/PATCH/DELETE), default 20 req/s
	MutateBurst   int `yaml:"mutate_burst"`   // burst above average, default 40
}

// ClusterConfig controls multi-node clustering (Phase 3).
// When Enabled is false (default), the system runs in single-node mode.
type ClusterConfig struct {
	Enabled        bool     `yaml:"enabled"`                   // enable cluster mode; default false
	NodeName       string   `yaml:"node_name,omitempty"`       // unique node name; defaults to hostname
	AdvertiseAddr  string   `yaml:"advertise_addr,omitempty"`  // address other nodes use to reach this one (host:port)
	SeedNodes      []string `yaml:"seed_nodes,omitempty"`      // initial nodes to contact for cluster join
	Services       []string `yaml:"services,omitempty"`        // services this node runs: ["postfix","dovecot","api","rspamd"]
	HeartbeatSec   int      `yaml:"heartbeat_sec,omitempty"`   // heartbeat interval in seconds; default 10
	LeaderLeaseSec int      `yaml:"leader_lease_sec,omitempty"` // leader lease duration in seconds; default 30
	PgBouncer      PgBouncerConfig `yaml:"pgbouncer"`
}

// PgBouncerConfig controls the PgBouncer connection pooler (Phase 3.3).
type PgBouncerConfig struct {
	Enabled        bool   `yaml:"enabled"`                    // include PgBouncer container; default false
	PoolMode       string `yaml:"pool_mode,omitempty"`        // "transaction" (default) or "session"
	DefaultPoolSize int   `yaml:"default_pool_size,omitempty"` // default 20
	MaxClientConn  int    `yaml:"max_client_conn,omitempty"`   // default 200
	ListenPort     int    `yaml:"listen_port,omitempty"`       // default 6432
}

// DefaultClusterConfig returns sensible defaults for clustering.
func DefaultClusterConfig() ClusterConfig {
	return ClusterConfig{
		Enabled:        false,
		HeartbeatSec:   10,
		LeaderLeaseSec: 30,
		PgBouncer: PgBouncerConfig{
			Enabled:        false,
			PoolMode:       "transaction",
			DefaultPoolSize: 20,
			MaxClientConn:  200,
			ListenPort:     6432,
		},
	}
}

// DefaultRateLimits returns sensible defaults for rate limiting.
func DefaultRateLimits() RateLimitConfig {
	return RateLimitConfig{
		AuthAverage:   10,
		AuthBurst:     20,
		APIAverage:    50,
		APIBurst:      100,
		MutateAverage: 20,
		MutateBurst:   40,
	}
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
	OIDC         OIDCSecrets          `yaml:"oidc,omitempty"`
	Cloudflare   *CloudflareSecrets   `yaml:"cloudflare,omitempty"`
	ValidonX     *ValidonXSecrets     `yaml:"validonx,omitempty"`
}

// DatabaseSecrets holds connection details and per-service credentials for
// the PostgreSQL database (three DB users per ADR-019).
//
// SuperuserPassword is the password for the built-in `postgres` superuser. It
// is only used by the Postgres container itself (POSTGRES_PASSWORD) and by the
// init-users.sh bootstrap script — application code always connects as one of
// the three least-privilege users.
type DatabaseSecrets struct {
	Host               string `yaml:"host"`
	Port               int    `yaml:"port"`
	Name               string `yaml:"name"`
	SuperuserPassword  string `yaml:"superuser_password"`
	APIUser            string `yaml:"api_user"`
	APIPassword        string `yaml:"api_password"`
	PostfixUser        string `yaml:"postfix_user"`
	PostfixPassword    string `yaml:"postfix_password"`
	DovecotUser        string `yaml:"dovecot_user"`
	DovecotPassword    string `yaml:"dovecot_password"`
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
	Secret              string `yaml:"secret"`                         // cookie / JWT signing key
	AdminEmail          string `yaml:"admin_email"`                    // initial admin, used by installer only
	AdminPassword       string `yaml:"admin_password"`                 // initial admin, used by installer only
	BackupEncryptionKey string `yaml:"backup_encryption_key"` // AES-256 encryption key for backups; required for production
}

// OrchestratorSecrets holds authentication credentials for internal HTTP calls
// between the API server and the orchestrator.
type OrchestratorSecrets struct {
	Token       string `yaml:"token"`                  // bearer token (Phase 1 fallback)
	MTLSCertDir string `yaml:"mtls_cert_dir,omitempty"` // directory containing internal CA + certs; enables mTLS when set
}

// DKIMSecrets stores the base path where per-domain DKIM private keys live.
type DKIMSecrets struct {
	KeyBasePath string `yaml:"key_base_path"` // default "/var/vectis/dkim"
}

// CloudflareSecrets is retained only so pre-rc27 secrets.yaml files still
// parse — the acme.sh sidecar that consumed this token was removed in rc27
// in favour of Traefik-based cert issuance + a cert-extractor sidecar.
// The field is ignored at runtime and can be deleted from secrets.yaml.
//
// Deprecated: unused; scheduled for removal once we're comfortable asking
// operators to drop the block from secrets.yaml.
type CloudflareSecrets struct {
	APIToken string `yaml:"api_token"`
}

// OIDCSecrets holds OIDC provider configurations for admin SSO.
type OIDCSecrets struct {
	Providers map[string]OIDCProviderConfig `yaml:"providers"`
}

// OIDCProviderConfig holds the credentials and settings for a single OIDC provider.
type OIDCProviderConfig struct {
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	DiscoveryURL string   `yaml:"discovery_url"` // e.g. https://accounts.google.com
	Scopes       []string `yaml:"scopes"`        // default: ["openid", "email", "profile"]
	Enabled      bool     `yaml:"enabled"`
}

// ValidonXSecrets holds credentials for the ValidonX licensing service.
// When nil, the system operates in free-tier mode with all basic features enabled.
type ValidonXSecrets struct {
	BaseURL        string `yaml:"base_url"`        // e.g. https://api.validonx.com
	ServiceKey     string `yaml:"service_key"`      // service authentication key
	TenantID       string `yaml:"tenant_id"`        // this server's tenant ID
	SubscriptionID string `yaml:"subscription_id"`  // this server's subscription ID
	ServerID       string `yaml:"server_id"`        // unique server identifier
}

// ValidonXConfigured returns true if ValidonX licensing secrets are present.
func (s *VectisSecrets) ValidonXConfigured() bool {
	return s != nil && s.ValidonX != nil && s.ValidonX.BaseURL != "" && s.ValidonX.ServiceKey != ""
}
