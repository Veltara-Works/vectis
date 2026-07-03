package api

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/valkey-io/valkey-go"

	"github.com/Veltara-Works/vectis/internal/audit"
	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/backup"
	"github.com/Veltara-Works/vectis/internal/cluster"
	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/dkim"
	"github.com/Veltara-Works/vectis/internal/engine"
	"github.com/Veltara-Works/vectis/internal/license"
	"github.com/Veltara-Works/vectis/internal/mail"
	"github.com/Veltara-Works/vectis/internal/mail/postfixlog"
	"github.com/Veltara-Works/vectis/internal/mailimport"
	vectismetrics "github.com/Veltara-Works/vectis/internal/metrics"
	"github.com/Veltara-Works/vectis/internal/monitor"
	"github.com/Veltara-Works/vectis/internal/orchestrator"
	"github.com/Veltara-Works/vectis/internal/policy"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/Veltara-Works/vectis/internal/retention"
	"github.com/Veltara-Works/vectis/internal/secretcrypto"
	vectistls "github.com/Veltara-Works/vectis/internal/tls"
	"github.com/Veltara-Works/vectis/internal/validonx"
)

// Server is the Vectis API server.
type Server struct {
	router     chi.Router
	httpServer *http.Server
	logger     *slog.Logger

	// Dependencies
	db                 *pgxpool.Pool
	vk                 valkey.Client
	sessions           *auth.SessionManager
	hostname           string
	internalToken      string // shared secret for service-to-service calls (tracking-link HMAC)
	inboundNotifyToken string // scoped token (derived from API secret) for Postfix inbound-notify → API
	dkimBasePath       string
	webDir             string
	genDir             string // directory for generated config files
	callbackBaseURL    string // public base URL (OIDC/SAML callbacks, SCIM meta.location)
	cfg                *config.VectisConfig
	secrets            *config.VectisSecrets
	orchClient         *orchestrator.Client

	// Repositories
	domains      *repository.DomainRepo
	mailboxes    *repository.MailboxRepo
	aliases      *repository.AliasRepo
	spamLists    *repository.SpamListRepo
	admins       *repository.AdminRepo
	adminDomains *repository.AdminDomainRepo
	apiKeys      *repository.APIKeyRepo
	webhooks     *repository.WebhookRepo
	abuseEvents  *repository.AbuseRepo
	audit        *repository.AuditRepo
	alerts       *repository.AlertRepo
	messages     *repository.MessageRepo
	mailStats    *repository.MailStatsRepo
	emailEvents  *repository.EmailEventRepo
	ipWarmup     *repository.IPWarmupRepo
	rblChecks    *repository.RBLCheckRepo
	fblReports   *repository.FBLReportRepo
	resetTokens  *repository.PasswordResetRepo
	scimTokens   *repository.SCIMTokenRepo

	erasureTombstones *repository.ErasureTombstoneRepo

	// Native IMAP import (admin-triggered external-account onboarding).
	importJobs    *repository.IMAPImportRepo
	dovecotTokens *repository.DovecotAuthTokenRepo

	// Notifications
	notifications *mail.NotificationSender

	// TOTP
	totpManager *auth.TOTPManager

	// OIDC
	oidcManager *auth.OIDCManager

	// SAML (Enterprise SSO)
	samlManager *auth.SAMLManager

	// Mail sending, webhooks, abuse detection
	mailSender        *mail.Sender
	webhookDispatcher *mail.WebhookDispatcher
	abuseDetector     *mail.AbuseDetector
	postfixTailer     *postfixlog.Tailer
	policyServer      *policy.Server
	// inboundAsync bounds the memory of fire-and-forget inbound processing
	// (full-message webhook, ARF parse) so a mail flood can't OOM the api
	// container with unbounded goroutines each holding a full message (#120).
	inboundAsync *inboundAsyncLimiter

	// resetLimiter rate-limits the password-reset endpoints per source IP and
	// per target email (audit D-L2). nil in bare test servers, which fall back
	// to no rate limiting.
	resetLimiter *fixedWindowLimiter

	// Sieve filter management
	sieveClient *mail.SieveClient

	// Deliverability services
	rblMonitor    *mail.RBLMonitor
	warmupManager *mail.WarmupManager

	// Clustering
	nodeMgr       *cluster.NodeManager
	rollingCoord  *cluster.RollingCoordinator
	clusterHealth *cluster.HealthChecker

	// Background services
	monitor          *monitor.Monitor
	alerter          *monitor.Alerter // shared by the health monitor and the backup scheduler's failure alert
	auditPruner      *audit.Pruner
	retentionSweeper *retention.Sweeper
	sessionCleaner   *auth.SessionCleaner
	importWorker     *mailimport.Worker
	backupScheduler  *backup.Scheduler
	backupSchedMu    sync.Mutex // serialises Start/Stop/Reload of backupScheduler
	usageReporter    *validonx.UsageReporter
	// licenseRefresher keeps the offline JWT verifier's keyset current in the
	// background. nil when no license token is configured in secrets.yaml — the
	// offline path is then inert and the gate runs HTTP-resolve/Free only.
	licenseRefresher *license.Refresher
	// featureGate is always non-nil. When ValidonX is not configured the
	// install runs as Free tier — only free-tier features pass; Pro/Enterprise
	// gates deny with 403 / 402. Pre-v0.1.6 the unconfigured branch was an
	// "allow everything" bypass; see feedback_featuregate_unconfigured_bypass.md.
	featureGate *validonx.FeatureGateService
}

// Config holds API server configuration.
type Config struct {
	ListenAddr          string
	SessionTTL          int // hours
	CookieSecret        string
	Hostname            string
	DKIMBasePath        string
	WebDir              string // path to static UI files (optional)
	GenDir              string // path to generated config output directory
	VectisCfg           *config.VectisConfig
	VectisSecrets       *config.VectisSecrets
	OrchestratorURL     string   // http://orchestrator:8081 or https://orchestrator:8081
	OrchestratorToken   string   // bearer token for orchestrator internal API (fallback)
	OrchestratorCertDir string   // mTLS certificate directory; when set, upgrades to mTLS
	CallbackBaseURL     string   // base URL for OIDC callbacks (e.g. https://mail.example.com)
	ServerIPs           []string // server IP addresses for RBL monitoring
	PostfixLogPath      string   // path to Postfix mail log for delivery/bounce event tailing; empty disables
}

// New creates a new API server with all routes registered.
func New(db *pgxpool.Pool, vk valkey.Client, cfg Config, logger *slog.Logger) *Server {
	// Self-heal DKIM key permissions on every startup. Pre-v0.1.6 keys were
	// written 0600 root, invisible to the rspamd worker (uid 100). Without
	// this pass, upgrading installs would still have outbound DKIM signing
	// silently broken even after the GenerateKey perm fix landed.
	if cfg.DKIMBasePath != "" {
		if err := dkim.RepairPerms(cfg.DKIMBasePath); err != nil {
			logger.Warn("dkim RepairPerms failed (non-fatal)", "error", err, "base_path", cfg.DKIMBasePath)
		}
	}
	// NB: secret-config permission self-heal (engine.RepairConfigPerms) lives in
	// the orchestrator, not here — the api only bind-mounts the rspamd subdir of
	// /var/vectis/generated, so it can't see the dovecot/postfix SQL conf files
	// that carry the DB role passwords.

	// Webhook signing secrets are encrypted at rest (P5-M10) with a key
	// derived from the API signing secret — no extra secret to provision.
	// Rotating cfg.CookieSecret therefore orphans existing webhook secrets
	// (they must be re-created), the same blast radius as rotating it
	// already has for sessions/JWTs.
	webhookEncKey := secretcrypto.DeriveKey([]byte(cfg.CookieSecret), "vectis-webhook-secret-v1")

	// The IMAP import source password is encrypted at rest with its own derived
	// key (same provisioning model as webhook secrets — no extra secret needed).
	importEncKey := secretcrypto.DeriveKey([]byte(cfg.CookieSecret), "vectis-imap-import-v1")

	s := &Server{
		logger:             logger,
		db:                 db,
		vk:                 vk,
		sessions:           auth.NewSessionManager(db, vk, cfg.SessionTTL, cfg.CookieSecret),
		hostname:           cfg.Hostname,
		internalToken:      cfg.CookieSecret,                                  // reuse API secret for tracking-link HMAC
		inboundNotifyToken: engine.DeriveInboundNotifyToken(cfg.CookieSecret), // scoped, not the master secret
		dkimBasePath:       cfg.DKIMBasePath,
		webDir:             cfg.WebDir,
		genDir:             cfg.GenDir,
		callbackBaseURL:    cfg.CallbackBaseURL,
		cfg:                cfg.VectisCfg,
		secrets:            cfg.VectisSecrets,
		inboundAsync:       newInboundAsyncLimiter(maxInboundAsyncBytes),
		resetLimiter:       newFixedWindowLimiter(5, 15*time.Minute),
		domains:            repository.NewDomainRepo(db),
		mailboxes:          repository.NewMailboxRepo(db),
		aliases:            repository.NewAliasRepo(db),
		spamLists:          repository.NewSpamListRepo(db),
		admins:             repository.NewAdminRepo(db),
		adminDomains:       repository.NewAdminDomainRepo(db),
		apiKeys:            repository.NewAPIKeyRepo(db),
		webhooks:           repository.NewWebhookRepo(db, webhookEncKey),
		abuseEvents:        repository.NewAbuseRepo(db),
		audit:              repository.NewAuditRepo(db),
		alerts:             repository.NewAlertRepo(db),
		messages:           repository.NewMessageRepo(db),
		mailStats:          repository.NewMailStatsRepo(db),
		emailEvents:        repository.NewEmailEventRepo(db),
		ipWarmup:           repository.NewIPWarmupRepo(db),
		rblChecks:          repository.NewRBLCheckRepo(db),
		fblReports:         repository.NewFBLReportRepo(db),
		resetTokens:        repository.NewPasswordResetRepo(db),
		scimTokens:         repository.NewSCIMTokenRepo(db),
		erasureTombstones:  repository.NewErasureTombstoneRepo(db),
		importJobs:         repository.NewIMAPImportRepo(db, importEncKey),
		dovecotTokens:      repository.NewDovecotAuthTokenRepo(db),
		totpManager:        auth.NewTOTPManager(cfg.CookieSecret, cfg.Hostname),
	}

	// Self-heal: encrypt any webhook signing secret still stored as plaintext
	// from before encryption at rest landed (P5-M10). Idempotent and non-fatal
	// — a failure leaves the legacy plaintext readable (Decrypt passes it
	// through), so delivery keeps working either way.
	if n, err := s.webhooks.EncryptLegacySecrets(context.Background()); err != nil {
		logger.Warn("webhook secret encryption pass failed (non-fatal)", "error", err)
	} else if n > 0 {
		logger.Info("encrypted legacy webhook secrets at rest", "count", n)
	}

	// Initialize orchestrator client — prefer mTLS, fall back to bearer token.
	if cfg.OrchestratorURL != "" {
		if cfg.OrchestratorCertDir != "" {
			tlsCfg, err := vectistls.NewClientTLSConfig(cfg.OrchestratorCertDir)
			if err != nil {
				logger.Error("failed to load orchestrator mTLS certs, falling back to bearer token", "error", err)
				if cfg.OrchestratorToken != "" {
					s.orchClient = orchestrator.NewClient(cfg.OrchestratorURL, cfg.OrchestratorToken)
				}
			} else {
				s.orchClient = orchestrator.NewMTLSClient(cfg.OrchestratorURL, tlsCfg)
				logger.Info("orchestrator client using mTLS")
			}
		} else if cfg.OrchestratorToken != "" {
			s.orchClient = orchestrator.NewClient(cfg.OrchestratorURL, cfg.OrchestratorToken)
		}
	}

	// Register Prometheus metrics collector on the default registry. In
	// production New is constructed once, but integration tests build many
	// Servers in a single process; a plain MustRegister panics on the second
	// call. An AlreadyRegisteredError means an equivalent collector (identical
	// Descs) is already present — harmless, so tolerate it. Any other error is
	// a genuine misconfiguration and still fails fast, matching MustRegister.
	if err := prometheus.Register(vectismetrics.NewCollector(db, logger.With("component", "metrics"))); err != nil {
		if _, ok := err.(prometheus.AlreadyRegisteredError); !ok {
			panic(err)
		}
	}

	// Initialize mail sender, notification sender, webhook dispatcher, and abuse detector.
	s.mailSender = mail.NewSender("vectis-postfix:25", cfg.Hostname, logger.With("component", "mail-sender"))
	s.notifications = mail.NewNotificationSender(s.mailSender, cfg.Hostname)
	s.webhookDispatcher = mail.NewWebhookDispatcher(s.webhooks, logger.With("component", "webhook-dispatcher"))
	s.abuseDetector = mail.NewAbuseDetector(vk, mail.DefaultAbuseConfig(), logger.With("component", "abuse-detector"))

	// Native IMAP import worker: runs admin-triggered external-account imports in
	// the background and recovers any left pending/running after a restart.
	importLogger := logger.With("component", "imap-import")
	importer := mailimport.NewImporter(s.importJobs, s.dovecotTokens, importLogger)
	s.importWorker = mailimport.NewWorker(importer, s.importJobs, importLogger)

	// Initialize Postfix log tailer if a log path is configured. The tailer
	// resolves Postfix queue_ids back to RFC 5322 Message-IDs and emits
	// mail.delivered / mail.bounced webhooks for outbound messages.
	if cfg.PostfixLogPath != "" {
		tailerLogger := logger.With("component", "postfix-log-tailer")
		emitter := postfixlog.NewWebhookEmitter(s.messages, s.webhookDispatcher, s.mailStats, tailerLogger)
		s.postfixTailer = postfixlog.New(postfixlog.Options{
			Path:    cfg.PostfixLogPath,
			Handler: emitter,
			Logger:  tailerLogger,
		})
	}

	// Initialize ValidonX licensing.
	//
	// Config precedence: validonx_config DB row > secrets.yaml > nil. The DB
	// row is populated by the admin UI License page (rc54+); secrets.yaml is
	// the install-time / scripted-deploy fallback. Either source must
	// provide base_url + service_key for the client to be Configured.
	//
	// FeatureGateService is always non-nil. When unconfigured the install runs
	// as Free tier — only free-tier features (basic_mail) pass; Pro/Enterprise
	// gates deny. Handlers can still call s.featureGate.* unconditionally.
	{
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var vxSecrets *config.ValidonXSecrets
		if cfg.VectisSecrets != nil {
			vxSecrets = cfg.VectisSecrets.ValidonX
		}
		runtimeCfg, err := validonx.LoadRuntimeConfig(ctx, db, vxSecrets)
		if err != nil {
			logger.Warn("failed to load validonx runtime config from DB; using secrets.yaml only",
				"error", err)
		}
		vxClient := validonx.NewClient(runtimeCfg.ToSecrets(), logger.With("component", "validonx"))
		s.featureGate = validonx.NewFeatureGateService(vxClient, db, logger.With("component", "validonx.gate"))
		if vxClient.Configured() {
			s.usageReporter = validonx.NewUsageReporter(vxClient, db, logger.With("component", "usage-reporter"))
			logger.Info("validonx licensing configured",
				"from_db", runtimeCfg.FromDB,
				"tenant_id", runtimeCfg.TenantID,
				"server_id", runtimeCfg.ServerID,
			)
		} else {
			logger.Info("validonx licensing not configured — running in free-tier mode")
		}
	}

	// Initialize the offline license verifier (Pharlux-pattern Ed25519 JWT).
	//
	// Additive to the ValidonX HTTP-resolve path above: when a license token is
	// configured in secrets.yaml, its offline verdict takes precedence in the
	// feature gate (JWT-wins-when-present). The JWKS layers (live HTTPS → cache
	// → embedded) are always available, so the verifier works air-gapped. The
	// Refresher's StartLicenseRefresher/StopLicenseRefresher lifecycle keeps the
	// keyset fresh; the verification hot path never touches the network.
	//
	// Inert when no token is configured — s.licenseRefresher stays nil and the
	// gate's offline source is unset, so behaviour is unchanged.
	if cfg.VectisSecrets != nil && cfg.VectisSecrets.OfflineConfigured() {
		lic := cfg.VectisSecrets.License
		resolver := license.NewResolver(lic.JWKSURL, lic.CachePath())
		provider := license.NewProvider(resolver)
		s.licenseRefresher = license.NewRefresher(provider, 0, logger.With("component", "license-refresher"))
		s.featureGate.SetOfflineLicense(validonx.NewOfflineLicense(provider, lic.Token, license.VMPolicy()))
		logger.Info("offline license verifier configured",
			"jwks_url", lic.JWKSURL, "jwks_cache_path", lic.CachePath())
	}

	// Initialize clustering if enabled.
	if cfg.VectisCfg != nil && cfg.VectisCfg.Cluster.Enabled {
		clusterCfg := cfg.VectisCfg.Cluster
		s.nodeMgr = cluster.NewNodeManager(db, clusterCfg, logger.With("component", "node-manager"))
		s.rollingCoord = cluster.NewRollingCoordinator(db, s.nodeMgr, logger.With("component", "rolling-coordinator"))
		s.clusterHealth = cluster.NewHealthChecker(s.nodeMgr, logger.With("component", "cluster-health"))
	}

	// Initialize Sieve client for ManageSieve protocol.
	s.sieveClient = mail.NewSieveClient("vectis-dovecot", "4190", logger.With("component", "sieve-client"))

	// Initialize RBL monitor if server IPs are configured.
	if len(cfg.ServerIPs) > 0 {
		s.rblMonitor = mail.NewRBLMonitor(s.rblChecks, cfg.ServerIPs, logger.With("component", "rbl-monitor"))
	}

	// Initialize IP warmup manager.
	s.warmupManager = mail.NewWarmupManager(s.ipWarmup, logger.With("component", "warmup-manager"))

	// Initialize OIDC manager if providers are configured.
	if cfg.VectisSecrets != nil && len(cfg.VectisSecrets.OIDC.Providers) > 0 && cfg.CallbackBaseURL != "" {
		ctx := context.Background()
		oidcMgr, err := auth.NewOIDCManager(ctx, vk, cfg.VectisSecrets.OIDC, cfg.CallbackBaseURL)
		if err != nil {
			logger.Error("failed to initialize OIDC providers", "error", err)
		} else if oidcMgr.HasProviders() {
			s.oidcManager = oidcMgr
			logger.Info("OIDC SSO enabled", "providers", oidcMgr.ListProviders())
		}
	}

	// Initialize SAML manager if providers are configured (Enterprise SSO).
	if cfg.VectisSecrets != nil && len(cfg.VectisSecrets.SAML.Providers) > 0 && cfg.CallbackBaseURL != "" {
		ctx := context.Background()
		samlMgr, err := auth.NewSAMLManager(ctx, vk, cfg.VectisSecrets.SAML, cfg.CallbackBaseURL)
		if err != nil {
			logger.Error("failed to initialize SAML providers", "error", err)
		} else if samlMgr.HasProviders() {
			s.samlManager = samlMgr
			logger.Info("SAML SSO enabled", "providers", samlMgr.ListProviders())
		}
	}

	s.router = s.buildRouter()
	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Start begins listening for HTTP requests.
func (s *Server) Start() error {
	// Precompute the login-timing dummy hash off the request path so the first
	// unknown-account login doesn't pay the one-time Argon2id cost. It's lazy
	// (sync.Once) so non-auth binaries never allocate the 64MB Argon2id buffer
	// — see auth.WarmDummyPasswordHash and auth.VerifyDummyPassword.
	go auth.WarmDummyPasswordHash()

	s.logger.Info("starting API server", "addr", s.httpServer.Addr)
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("listen: %w", err)
	}
	return nil
}

// StartMonitor initialises and starts the background health monitor. It
// should be called after the server is constructed but before Start().
func (s *Server) StartMonitor() {
	// Fall back to the installer's admin email when alerts.email.recipients
	// is left empty — avoids forcing the operator to write the same address
	// in two files just to get container-health alerts.
	emailCfg := s.cfg.Alerts.Email
	if len(emailCfg.Recipients) == 0 && s.secrets.API.AdminEmail != "" {
		emailCfg.Recipients = []string{s.secrets.API.AdminEmail}
	}

	// Build the Alerter once and retain it on the Server: the health monitor
	// uses it for its checks, and the backup scheduler reuses it to alert on
	// scheduled-backup failures (see startBackupSchedulerLocked).
	s.alerter = monitor.NewAlerter(
		s.alerts,
		emailCfg,
		s.cfg.Alerts.Webhook,
		s.hostname,
		s.logger.With("component", "alerter"),
	)

	monCfg := monitor.DefaultConfig()
	if s.dkimBasePath != "" {
		// Certs directory sits alongside the DKIM key base path.
		monCfg.CertDir = s.dkimBasePath + "/../certs"
	}

	s.monitor = monitor.New(s.db, s.vk, s.alerter, monCfg, s.logger.With("component", "monitor"))
	// Feed the LIVE effective backup settings into the monitor so it can flag a
	// stale/absent last-successful-backup (C-1). A provider (not a snapshot) so a
	// runtime schedule change via the admin UI takes effect without a restart —
	// otherwise a shortened cadence would leave the staleness threshold pinned to
	// the old, longer interval and under-alert.
	s.monitor.SetBackupSettingsProvider(func() (bool, string, string) {
		st := s.effectiveBackupSettings(context.Background())
		return st.Enabled, st.Schedule, st.Timezone
	})
	s.monitor.Start()
}

// StopMonitor stops the background health monitor if it is running.
func (s *Server) StopMonitor() {
	if s.monitor != nil {
		s.monitor.Stop()
	}
}

// StartSessionCleaner starts the background job that deletes expired
// session rows from Postgres (Valkey entries auto-expire via EX).
func (s *Server) StartSessionCleaner() {
	s.sessionCleaner = auth.NewSessionCleaner(
		s.sessions,
		auth.DefaultSessionCleanerConfig(),
		s.logger.With("component", "session-cleaner"),
	)
	s.sessionCleaner.Start()
}

// StopSessionCleaner stops the background session cleaner if it is running.
func (s *Server) StopSessionCleaner() {
	if s.sessionCleaner != nil {
		s.sessionCleaner.Stop()
	}
}

// StartAuditPruner initialises and starts the background audit log pruner.
func (s *Server) StartAuditPruner() {
	cfg := audit.DefaultPrunerConfig()
	if s.cfg != nil && s.cfg.Audit.RetentionDays > 0 {
		cfg.RetentionDays = s.cfg.Audit.RetentionDays
	}

	s.auditPruner = audit.NewPruner(
		s.audit,
		cfg,
		s.logger.With("component", "audit-pruner"),
	)
	s.auditPruner.Start()
}

// StopAuditPruner stops the background audit log pruner if it is running.
func (s *Server) StopAuditPruner() {
	if s.auditPruner != nil {
		s.auditPruner.Stop()
	}
}

// StartRetentionSweeper initialises and starts the data-retention sweeper,
// which purges engagement events + message metadata past their window. It is a
// no-op when no retention window is configured (config.yaml retention:).
func (s *Server) StartRetentionSweeper() {
	// Opt-in by design: a retention window applies only when the operator sets it
	// in config.yaml (retention:). 0 or absent = keep forever, so an unconfigured
	// install never deletes data — no surprise purges on upgrade. (Audit-log
	// retention is separate, owned by the audit pruner.)
	cfg := retention.Config{RunInterval: 24 * time.Hour}
	if s.cfg != nil {
		cfg.TrackingEventDays = s.cfg.Retention.TrackingEventDays
		cfg.MessageMetadataDays = s.cfg.Retention.MessageMetadataDays
		if s.cfg.Retention.RunIntervalHours > 0 {
			cfg.RunInterval = time.Duration(s.cfg.Retention.RunIntervalHours) * time.Hour
		}
	}
	s.retentionSweeper = retention.NewSweeper(
		s.emailEvents, s.messages, s.audit, cfg,
		s.logger.With("component", "retention-sweeper"),
	)
	s.retentionSweeper.Start()
}

// StopRetentionSweeper stops the retention sweeper if it is running.
func (s *Server) StopRetentionSweeper() {
	if s.retentionSweeper != nil {
		s.retentionSweeper.Stop()
	}
}

// effectiveBackupSettings returns the runtime backup settings: the
// backup_config DB row when present, otherwise the file config (config.yaml
// `backup:`). Mirrors how validonx_config / branding_config overlay their
// file-config equivalents.
func (s *Server) effectiveBackupSettings(ctx context.Context) backup.Settings {
	if s.db != nil {
		if st, err := backup.LoadSettings(ctx, s.db); err != nil {
			s.logger.Warn("load backup settings; falling back to file config", "error", err)
		} else if st.FromDB {
			return st
		}
	}
	st := backup.Settings{}
	if s.cfg != nil {
		st.Enabled = s.cfg.Backup.Enabled
		st.Schedule = s.cfg.Backup.Schedule
		st.Timezone = s.cfg.Backup.Timezone
		st.RetainDays = s.cfg.Backup.RetainDays
	}
	return st
}

// ReconcileIncompleteBackups marks any backup job still in a non-terminal state
// (pending/running) as failed. It MUST be called once at startup, synchronously,
// BEFORE StartBackupScheduler and before the server serves create requests: the
// backup manager is a single writer, so any job left pending/running at boot was
// orphaned by a crash or restart and will otherwise linger forever, masking the
// true "no successful backup" state (the invisibility defect this fix targets).
// Failures are logged, never fatal — a marking error must not block boot.
func (s *Server) ReconcileIncompleteBackups() {
	if s.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	n, err := repository.NewBackupRepo(s.db).FailIncomplete(ctx, "server restarted; job interrupted")
	if err != nil {
		s.logger.Error("backup: crash-reconcile of interrupted jobs failed", "error", err)
		return
	}
	if n > 0 {
		s.logger.Warn("backup: marked interrupted jobs failed on startup", "count", n)
	}
}

// StartBackupScheduler starts the periodic backup scheduler when backups are
// enabled. It is a no-op (with a log line) when disabled or misconfigured, so
// a bad schedule never crashes the server — it just doesn't run scheduled
// backups. Settings come from the DB overlay (effectiveBackupSettings).
func (s *Server) StartBackupScheduler() {
	s.backupSchedMu.Lock()
	defer s.backupSchedMu.Unlock()
	s.startBackupSchedulerLocked()
}

// startBackupSchedulerLocked is the unsynchronised body shared by Start and
// Reload. Callers must hold backupSchedMu.
func (s *Server) startBackupSchedulerLocked() {
	st := s.effectiveBackupSettings(context.Background())
	if !st.Enabled {
		s.logger.Info("backup scheduler disabled (backup.enabled=false)")
		return
	}
	mgr := s.backupManager()
	if mgr == nil {
		s.logger.Error("backup scheduler not started: backup manager unavailable")
		return
	}
	sched, err := backup.NewScheduler(mgr, backup.SchedulerConfig{
		Schedule:   st.Schedule,
		Timezone:   st.Timezone,
		RetainDays: st.RetainDays,
	}, s.logger.With("component", "backup-scheduler"))
	if err != nil {
		s.logger.Error("backup scheduler not started: invalid schedule", "error", err)
		return
	}
	// C-2: a scheduled backup failure must be visible. The scheduled path calls
	// mgr.Create synchronously and never fires the onComplete callback, so the
	// notification wiring on the async/UI path is dead here — alert via the
	// shared Alerter instead. CRITICAL bypasses the 15-min dedup so a nightly
	// failure is never suppressed. Injected as a callback so internal/backup
	// never imports internal/monitor (avoids an import cycle with C-1).
	if s.alerter != nil {
		alerter := s.alerter
		sched.SetOnError(func(ctx context.Context, err error) {
			alerter.Send(ctx, "CRITICAL", "backup", "scheduled backup failed: "+err.Error())
		})
	}
	s.backupScheduler = sched
	s.backupScheduler.Start()
}

// StopBackupScheduler stops the backup scheduler if it is running.
func (s *Server) StopBackupScheduler() {
	s.backupSchedMu.Lock()
	defer s.backupSchedMu.Unlock()
	s.stopBackupSchedulerLocked()
}

// stopBackupSchedulerLocked stops + clears the scheduler. Callers must hold
// backupSchedMu. Clearing the pointer makes a subsequent Stop a safe no-op
// (the underlying Stop closes a channel, which must not happen twice).
func (s *Server) stopBackupSchedulerLocked() {
	if s.backupScheduler != nil {
		s.backupScheduler.Stop()
		s.backupScheduler = nil
	}
}

// ReloadBackupScheduler restarts the scheduler from the current effective
// settings. Called after the admin UI saves new backup settings so a schedule
// or timezone change takes effect immediately, without a container restart.
func (s *Server) ReloadBackupScheduler() {
	s.backupSchedMu.Lock()
	defer s.backupSchedMu.Unlock()
	s.stopBackupSchedulerLocked()
	s.startBackupSchedulerLocked()
}

// StartWebhookDispatcher starts the webhook retry worker.
func (s *Server) StartWebhookDispatcher() {
	if s.webhookDispatcher != nil {
		s.webhookDispatcher.Start()
	}
}

// StopWebhookDispatcher stops the webhook retry worker.
func (s *Server) StopWebhookDispatcher() {
	if s.webhookDispatcher != nil {
		s.webhookDispatcher.Stop()
	}
}

// StartImportWorker starts the IMAP import background worker (and recovers any
// pending/running jobs left by a previous run).
func (s *Server) StartImportWorker() {
	if s.importWorker != nil {
		s.importWorker.Start()
	}
}

// StopImportWorker stops the IMAP import background worker.
func (s *Server) StopImportWorker() {
	if s.importWorker != nil {
		s.importWorker.Stop()
	}
}

// StartPostfixLogTailer begins tailing the Postfix mail log for delivery
// and bounce events that get translated into mail.delivered / mail.bounced
// webhook dispatches. No-op when PostfixLogPath is unset.
func (s *Server) StartPostfixLogTailer() {
	if s.postfixTailer != nil {
		s.postfixTailer.Start()
	}
}

// StopPostfixLogTailer stops the Postfix log tailer if running.
func (s *Server) StopPostfixLogTailer() {
	if s.postfixTailer != nil {
		s.postfixTailer.Stop()
	}
}

// StartUsageReporter starts the ValidonX usage metrics reporter.
func (s *Server) StartUsageReporter() {
	if s.usageReporter != nil {
		s.usageReporter.Start()
	}
}

// EnsureRspamdConfigFresh re-runs the per-domain rspamd config render on
// startup so the on-disk Lua extension + four allow/block map files +
// settings.conf reflect this binary's templates and the live database
// state. Closes the upgrade-staleness gap surfaced on the v0.1.1 →
// v0.1.3 sysadmin1001 walk: the old api wrote the rspamd files at
// install/CRUD time and they were never refreshed by the upgrade —
// leaving the previous-version Lua (with the v ~= nil bug) on disk
// even after the api container moved to v0.1.3.
//
// Async to avoid blocking startup; rspamd reload is best-effort and
// only matters for an immediate behaviour change. If reload fails
// because rspamd hasn't started yet (race during stack-up), rspamd
// will pick up the new content on its own first read of the maps.
func (s *Server) EnsureRspamdConfigFresh() {
	go func() {
		s.regenerateRspamdSpamConfig()
	}()
}

// StopUsageReporter stops the ValidonX usage metrics reporter.
func (s *Server) StopUsageReporter() {
	if s.usageReporter != nil {
		s.usageReporter.Stop()
	}
}

// StartLicenseRefresher performs the synchronous initial JWKS load and starts
// the background refresh loop for the offline license verifier. No-op when no
// license token is configured. A start failure (every JWKS layer including the
// embedded key fails — a build/config fault, not a transient outage) is logged
// and the offline path is left inert: Provider.Current() stays nil, so the gate
// falls through to the HTTP-resolve/Free path. It never aborts server startup.
func (s *Server) StartLicenseRefresher() {
	if s.licenseRefresher == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	if err := s.licenseRefresher.Start(ctx); err != nil {
		s.logger.Error("license jwks refresher failed to start; offline license inert", "error", err)
	}
}

// StopLicenseRefresher halts the background JWKS refresh loop.
func (s *Server) StopLicenseRefresher() {
	if s.licenseRefresher != nil {
		s.licenseRefresher.Stop()
	}
}

// StartCluster registers this node and starts the heartbeat/leader election loop.
func (s *Server) StartCluster() {
	if s.nodeMgr != nil {
		ctx := context.Background()
		nodeID, err := s.nodeMgr.Register(ctx)
		if err != nil {
			s.logger.Error("cluster node registration failed", "error", err)
			return
		}
		s.logger.Info("cluster node registered", "node_id", nodeID)
		s.nodeMgr.Start()
	}
}

// StopCluster gracefully stops the cluster node manager.
func (s *Server) StopCluster() {
	if s.nodeMgr != nil {
		s.nodeMgr.Stop()
	}
}

// StartRBLMonitor starts the background RBL monitoring loop.
func (s *Server) StartRBLMonitor() {
	if s.rblMonitor != nil {
		s.rblMonitor.Start()
	}
}

// StopRBLMonitor stops the RBL monitor.
func (s *Server) StopRBLMonitor() {
	if s.rblMonitor != nil {
		s.rblMonitor.Stop()
	}
}

// StartWarmupManager starts the background IP warmup schedule manager.
func (s *Server) StartWarmupManager() {
	if s.warmupManager != nil {
		s.warmupManager.Start()
	}
}

// StopWarmupManager stops the warmup manager.
func (s *Server) StopWarmupManager() {
	if s.warmupManager != nil {
		s.warmupManager.Stop()
	}
}

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down API server")
	s.StopMonitor()
	s.StopAuditPruner()
	s.StopRetentionSweeper()
	s.StopSessionCleaner()
	s.StopImportWorker()
	s.StopBackupScheduler()
	s.StopWebhookDispatcher()
	s.StopPostfixLogTailer()
	s.StopUsageReporter()
	s.StopLicenseRefresher()
	s.StopRBLMonitor()
	s.StopWarmupManager()
	s.StopCluster()
	s.StopPolicyServer()
	return s.httpServer.Shutdown(ctx)
}

// Handler returns the HTTP handler for testing.
func (s *Server) Handler() http.Handler {
	return s.router
}

// backupManager creates a backup.Manager from the server's config and secrets.
// Returns nil if the required database or secrets are not available.
func (s *Server) backupManager() *backup.Manager {
	if s.db == nil || s.secrets == nil {
		return nil
	}

	cfg := backup.DefaultConfig()
	cfg.DBHost = s.secrets.Database.Host
	cfg.DBPort = s.secrets.Database.Port
	cfg.DBName = s.secrets.Database.Name
	cfg.DBUser = s.secrets.Database.APIUser
	cfg.DBPassword = s.secrets.Database.APIPassword
	cfg.SuperuserPassword = s.secrets.Database.SuperuserPassword
	if s.secrets.DKIM.KeyBasePath != "" {
		cfg.DKIMDir = s.secrets.DKIM.KeyBasePath
	}

	// Encryption key for backup archives. Use dedicated key if set, otherwise
	// fall back to the API secret so encryption is on by default.
	if s.secrets.API.BackupEncryptionKey != "" {
		cfg.EncryptionKey = s.secrets.API.BackupEncryptionKey
	} else if s.secrets.API.Secret != "" {
		cfg.EncryptionKey = s.secrets.API.Secret
	}

	mgr := backup.NewManager(s.db, s.logger.With("component", "backup"), cfg)

	// Wire up backup completion notifications.
	if s.notifications != nil && s.secrets.API.AdminEmail != "" {
		adminEmail := s.secrets.API.AdminEmail
		mgr.SetOnComplete(func(path string, sizeMB int64, durationSecs int, err error) {
			if err != nil {
				if notifyErr := s.notifications.SendBackupFailed(adminEmail, err.Error()); notifyErr != nil {
					s.logger.Error("send backup failed notification", "error", notifyErr)
				}
			} else {
				if notifyErr := s.notifications.SendBackupComplete(adminEmail, path, sizeMB, durationSecs); notifyErr != nil {
					s.logger.Error("send backup complete notification", "error", notifyErr)
				}
			}
		})
	}

	return mgr
}

func (s *Server) buildRouter() chi.Router {
	r := chi.NewRouter()

	// Global middleware.
	r.Use(chimw.RealIP)
	r.Use(securityHeaders)
	r.Use(requestIDMiddleware)
	r.Use(s.loggingMiddleware)
	r.Use(chimw.Recoverer)

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(jsonContentType)
		// Public endpoints.
		r.Get("/health", s.handleHealth)
		r.Get("/version", s.handleVersion)
		// NOTE: /metrics/prometheus is NOT public — it is registered behind
		// requireSuperAdmin in the authenticated group below (G-M2). The bare
		// promhttp collector exposes cross-tenant domain/mailbox/admin counts,
		// so it must not be reachable unauthenticated. No bundled service
		// scrapes it; an external scraper authenticates with a super_admin
		// API-key bearer token.
		r.With(chimw.Throttle(5)).Post("/auth/login", s.handleLogin)
		r.With(chimw.Throttle(3), s.rateLimitByIP(s.resetLimiter)).Post("/auth/reset-request", s.handleRequestPasswordReset)
		r.With(chimw.Throttle(3), s.rateLimitByIP(s.resetLimiter)).Post("/auth/reset-password", s.handleResetPassword)

		// Internal service-to-service endpoints (token-authenticated, not session).
		r.Post("/internal/inbound", s.handleInboundNotify)

		// ValidonX-facing license revoke webhook. HMAC-authenticated over the
		// raw body (X-Vectis-Signature: sha256=<hex>), NOT session-authed — the
		// caller is ValidonX, not a browser. Probe-resistant 401 when the
		// offline verifier or webhook_secret is not configured.
		r.Post("/admin/license/revoke", s.handleLicenseRevoke)

		// Public tracking endpoints (no auth — must work in email clients).
		r.Get("/track/open/{token}", s.handleTrackOpen)
		r.Get("/track/click/{token}", s.handleTrackClick)

		// OIDC SSO (public — browser redirects).
		// providers handler filters its own list against HasFeature(oidc_sso),
		// so Free installs render no SSO buttons; login + callback carry the
		// content-negotiated gate as defence in depth (handles direct hits
		// and stale callbacks after a license downgrade).
		r.Get("/auth/oidc/providers", s.handleOIDCProviders)
		oidcGate := s.featureGate.FeatureGateBrowser(
			validonx.FeatureOIDCSSO,
			"OIDC single sign-on",
			"https://vectismail.com/pricing",
		)
		r.With(oidcGate).Get("/auth/oidc/login/{provider}", s.handleOIDCLogin)
		r.With(oidcGate).Get("/auth/oidc/callback/{provider}", s.handleOIDCCallback)

		// SAML 2.0 SSO (Enterprise — public browser redirects, SP-initiated).
		// providers handler filters its own list against HasFeature(saml_sso);
		// login + ACS carry the content-negotiated gate as defence in depth.
		// The ACS is POST (HTTP-POST binding) — its authenticity proof is the
		// signed assertion + RelayState, so it sits outside any session-CSRF
		// group, exactly like the OIDC GET callback. Metadata is public (no
		// secrets: entityID + ACS URL + SP cert).
		r.Get("/auth/saml/providers", s.handleSAMLProviders)
		r.Get("/auth/saml/metadata/{provider}", s.handleSAMLMetadata)
		samlGate := s.featureGate.FeatureGateBrowser(
			validonx.FeatureSAMLSSO,
			"SAML single sign-on",
			"https://vectismail.com/pricing",
		)
		r.With(samlGate).Get("/auth/saml/login/{provider}", s.handleSAMLLogin)
		r.With(samlGate).Post("/auth/saml/acs/{provider}", s.handleSAMLACS)

		// Authenticated endpoints.
		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)
			// CSRF defence in depth for cookie sessions (#127). After auth so
			// only authenticated cookie requests reach it; skips Bearer/API-key.
			r.Use(s.csrfProtect)

			// Auth management — all authenticated roles.
			r.Get("/auth/me", s.handleMe)
			r.Post("/auth/logout", s.handleLogout)
			r.Post("/auth/logout-all", s.handleLogoutAll)
			r.Get("/auth/sessions", s.handleListSessions)
			r.Delete("/auth/sessions/{sessionID}", s.handleDeleteSession)

			// TOTP MFA — all authenticated roles.
			r.Post("/auth/totp/setup", s.handleTOTPSetup)
			r.Post("/auth/totp/verify", s.handleTOTPVerify)
			r.Delete("/auth/totp", s.handleTOTPDisable)

			// OIDC management — all authenticated roles.
			r.Delete("/auth/oidc/disconnect", s.handleOIDCDisconnect)
			r.Post("/auth/saml/disconnect", s.handleSAMLDisconnect)

			// Domains collection — list + create (all roles; scoping in handler).
			r.Get("/domains", s.handleListDomains)
			r.With(requireAdminOrAbove()).Post("/domains", s.handleCreateDomain)

			// Domain-scoped subtree. requireDomainAccess is the single R1 choke
			// point: every /domains/{domainID}/... route — current and future —
			// inherits API-key-scope + domain_admin enforcement, so no handler
			// can silently skip it (the #119 scope class). Per-route RBAC and
			// Pro feature gates layer on top. advancedSpamGate is defined here
			// (was inline below) so the spam-list routes can join the subtree.
			advancedSpamGate := s.featureGate.FeatureGate(validonx.FeatureAdvancedSpam)
			r.Route("/domains/{domainID}", func(r chi.Router) {
				r.Use(s.requireDomainAccess)

				// Reads — all roles (scope already enforced by the choke point).
				r.Get("/", s.handleGetDomain)
				r.Get("/dkim", s.handleGetDKIM)
				r.Get("/deliverability", s.handleDeliverability)

				// Mutations — admin and super_admin only.
				r.With(requireAdminOrAbove()).Patch("/", s.handleUpdateDomain)
				r.With(requireAdminOrAbove()).Delete("/", s.handleDeleteDomain)
				r.With(requireAdminOrAbove()).Post("/dkim/generate", s.handleGenerateDKIM)
				r.With(requireAdminOrAbove()).Post("/dkim/rotate", s.handleRotateDKIM)
				r.With(requireAdminOrAbove()).Post("/verify", s.handleVerifyDomain)

				// Per-domain allow/block lists — Pro feature (Advanced Spam).
				// The field-level extensions to PATCH /domains/{id}
				// (reject_threshold, greylist_enabled) stay in handle_domains.go
				// since the domain CRUD route must remain open to Free for
				// ungated fields like spam_threshold.
				r.With(advancedSpamGate, requireAdminOrAbove()).Get("/spam-lists", s.handleListSpamListEntries)
				r.With(advancedSpamGate, requireAdminOrAbove()).Post("/spam-lists", s.handleCreateSpamListEntry)
				r.With(advancedSpamGate, requireAdminOrAbove()).Delete("/spam-lists/{entryID}", s.handleDeleteSpamListEntry)
			})

			// Mailboxes — all roles (domain_admin scoped in handlers).
			r.Get("/mailboxes", s.handleListMailboxes)
			r.Post("/mailboxes", s.handleCreateMailbox)
			r.Get("/mailboxes/{mailboxID}", s.handleGetMailbox)
			r.Patch("/mailboxes/{mailboxID}", s.handleUpdateMailbox)
			r.Delete("/mailboxes/{mailboxID}", s.handleDeleteMailbox)

			// Aliases — all roles (domain_admin scoped in handlers).
			r.Get("/aliases", s.handleListAliases)
			r.Post("/aliases", s.handleCreateAlias)
			r.Get("/aliases/{aliasID}", s.handleGetAlias)
			r.Patch("/aliases/{aliasID}", s.handleUpdateAlias)
			r.Delete("/aliases/{aliasID}", s.handleDeleteAlias)

			// Admins — super_admin only for mutations.
			r.Get("/admins", s.handleListAdmins)
			r.With(requireSuperAdmin()).Post("/admins", s.handleCreateAdmin)
			r.With(requireSuperAdmin()).Patch("/admins/{adminID}", s.handleUpdateAdmin)
			r.With(requireSuperAdmin()).Delete("/admins/{adminID}", s.handleDeleteAdmin)

			// Sending API — all roles (domain scoping enforced in handler).
			r.Post("/send", s.handleSend)
			r.Post("/send/batch", s.handleBatchSend)

			// Messages (Storage API) — all roles (domain scoping in handler).
			r.Get("/messages", s.handleListMessages)
			r.Get("/messages/{messageID}", s.handleGetMessage)

			// API keys — all roles can manage their own keys.
			r.Get("/api-keys", s.handleListAPIKeys)
			r.Post("/api-keys", s.handleCreateAPIKey)
			r.Delete("/api-keys/{keyID}", s.handleRevokeAPIKey)

			// Webhooks — admin and super_admin.
			r.With(requireAdminOrAbove()).Get("/webhooks", s.handleListWebhooks)
			r.With(requireAdminOrAbove()).Post("/webhooks", s.handleCreateWebhook)
			r.With(requireAdminOrAbove()).Delete("/webhooks/{webhookID}", s.handleDeleteWebhook)

			// Audit log — super_admin only (handler returns platform-wide entries unfiltered).
			r.With(requireSuperAdmin()).Get("/audit", s.handleListAudit)
			r.With(requireSuperAdmin()).Get("/audit/export", s.handleExportAudit)

			// DSAR — GDPR Art.15 access + Art.17 erasure. Super_admin only AND
			// Enterprise-gated (the dsar feature). Erasure is irreversible and
			// writes a restore-surviving tombstone.
			dsarGate := s.featureGate.FeatureGate(validonx.FeatureDSAR)
			r.With(requireSuperAdmin(), dsarGate).Get("/dsar/export", s.handleDSARExport)
			r.With(requireSuperAdmin(), dsarGate).Post("/dsar/erase", s.handleDSARErase)
			r.With(requireSuperAdmin(), dsarGate).Get("/dsar/erasures", s.handleDSARListErasures)

			// Sieve filter management — all roles (domain scoping in handler).
			r.Get("/mailboxes/{mailboxID}/sieve", s.handleListSieveScripts)
			r.Get("/mailboxes/{mailboxID}/sieve/{scriptName}", s.handleGetSieveScript)
			r.Put("/mailboxes/{mailboxID}/sieve", s.handlePutSieveScript)
			r.Delete("/mailboxes/{mailboxID}/sieve/{scriptName}", s.handleDeleteSieveScript)

			// Log search — super_admin only.
			r.With(requireSuperAdmin()).Get("/logs/search", s.handleLogSearch)

			// Engagement tracking stats — admin and super_admin, and a Pro
			// feature: the open/click analytics these expose are the same
			// FeatureAnalytics surface as /analytics below, so gate them the
			// same way. The public /track/* collection endpoints (above) stay
			// open — email clients must reach them regardless of tier.
			trackingGate := s.featureGate.FeatureGate(validonx.FeatureAnalytics)
			r.With(requireAdminOrAbove(), trackingGate).Get("/tracking/stats", s.handleTrackingStats)
			r.With(requireAdminOrAbove(), trackingGate).Get("/tracking/messages/{messageID}", s.handleMessageEngagement)
			r.With(requireAdminOrAbove(), trackingGate).Get("/tracking/messages/{messageID}/events", s.handleMessageEngagementEvents)

			// Abuse detection — admin and super_admin.
			r.With(requireAdminOrAbove()).Get("/abuse/dashboard", s.handleAbuseDashboard)
			r.With(requireAdminOrAbove()).Get("/abuse/events", s.handleListAbuseEvents)
			r.With(requireAdminOrAbove()).Post("/abuse/events/{eventID}/resolve", s.handleResolveAbuseEvent)
			r.With(requireAdminOrAbove()).Post("/abuse/mailboxes/{mailboxID}/suspend", s.handleSuspendMailbox)
			r.With(requireAdminOrAbove()).Post("/abuse/mailboxes/{mailboxID}/unsuspend", s.handleUnsuspendMailbox)

			// Admin impersonation — admin and super_admin.
			r.With(requireAdminOrAbove()).Post("/mailboxes/{mailboxID}/impersonate", s.handleImpersonate)
			r.With(requireAdminOrAbove()).Delete("/mailboxes/{mailboxID}/impersonate", s.handleRevokeImpersonation)

			// Native IMAP import — admin and super_admin (handles source credentials
			// and acts AS the mailbox). Domain scoping enforced per mailbox.
			r.With(requireAdminOrAbove()).Post("/mailboxes/{mailboxID}/import", s.handleCreateImport)
			r.With(requireAdminOrAbove()).Get("/mailboxes/{mailboxID}/imports", s.handleListImports)
			r.With(requireAdminOrAbove()).Get("/mailboxes/{mailboxID}/imports/{jobID}", s.handleGetImport)
			r.With(requireAdminOrAbove()).Post("/mailboxes/{mailboxID}/imports/{jobID}/cancel", s.handleCancelImport)

			// Per-domain analytics — Pro feature; gated by FeatureGate.
			// Free installs (ValidonX unconfigured): 403 FEATURE_NOT_AVAILABLE
			// since v0.1.6. Authenticated users on a paying customer with
			// active Pro license: 200. Cancelled/lapsed Pro license past
			// 30-day grace: 403 LICENSE_EXPIRED.
			r.With(s.featureGate.FeatureGate(validonx.FeatureAnalytics)).
				Get("/analytics", s.handleDomainAnalytics)

			// License management — super_admin only. The License page is
			// where customers paste their ValidonX subscription_id post-checkout
			// to activate Pro/Enterprise. POST validates against ValidonX,
			// persists to validonx_config, and atomically swaps the running
			// gate client (no api restart required).
			r.With(requireSuperAdmin()).Get("/license", s.handleGetLicense)
			r.With(requireSuperAdmin()).Post("/license", s.handleSetLicense)
			r.With(requireSuperAdmin()).Delete("/license", s.handleDeleteLicense)

			// SCIM token management — super_admin only AND Enterprise-gated
			// (FeatureSCIM). Mints/rotates/revokes the Bearer token the IdP
			// uses against /scim/v2. The token-mgmt endpoints share the SCIM
			// feature gate so a non-Enterprise admin can't mint tokens that
			// the /scim/v2 group would only 403 anyway. Lives on the
			// License/SSO page. POST rotates (revokes prior active token).
			scimTokenGate := s.featureGate.FeatureGate(validonx.FeatureSCIM)
			r.With(requireSuperAdmin(), scimTokenGate).Get("/scim-tokens", s.handleListSCIMTokens)
			r.With(requireSuperAdmin(), scimTokenGate).Post("/scim-tokens", s.handleCreateSCIMToken)
			r.With(requireSuperAdmin(), scimTokenGate).Delete("/scim-tokens/{tokenID}", s.handleRevokeSCIMToken)

			// Customer account / billing portal — super_admin only.
			// Mints a Stripe Customer Portal session via ValidonX and
			// returns the URL the admin UI should redirect to. Used by
			// the /account/billing page so the customer never sees the
			// ValidonX brand. Unlike the License gate, this does NOT
			// require an active license — past_due / cancelled customers
			// must be able to reach the portal to reactivate.
			r.With(requireSuperAdmin()).Post("/account/billing-portal-session", s.handleBillingPortalSession)

			// In-product "Buy Pro" checkout — super_admin only.
			// Mints a Stripe Checkout session via ValidonX's Customer #1
			// partner-key endpoint so a Free install can buy Pro without
			// leaving the admin UI. Does NOT require an existing license
			// (the whole point is bootstrapping one). Returns the URL the
			// admin UI navigates to.
			r.With(requireSuperAdmin()).Post("/account/upgrade-checkout-session", s.handleUpgradeCheckoutSession)

			// Branding — super_admin only. GET is unauthenticated-feature-wise
			// (Free installs hit it on every page load to render defaults);
			// PUT/DELETE require the custom_branding Pro feature.
			brandingGate := s.featureGate.FeatureGate(validonx.FeatureCustomBranding)
			r.With(requireSuperAdmin()).Get("/branding", s.handleGetBranding)
			r.With(requireSuperAdmin(), brandingGate).Put("/branding", s.handleSetBranding)
			r.With(requireSuperAdmin(), brandingGate).Delete("/branding", s.handleDeleteBranding)

			// Advanced deliverability — super_admin only.
			r.With(requireSuperAdmin()).Get("/deliverability/warmup", s.handleListWarmup)
			r.With(requireSuperAdmin()).Post("/deliverability/warmup", s.handleCreateWarmup)
			r.With(requireSuperAdmin()).Delete("/deliverability/warmup/{warmupID}", s.handleDeleteWarmup)
			r.With(requireSuperAdmin()).Get("/deliverability/rbl", s.handleRBLStatus)
			r.With(requireSuperAdmin()).Post("/deliverability/rbl/check", s.handleRBLCheckNow)
			r.With(requireSuperAdmin()).Get("/deliverability/fbl", s.handleListFBLReports)
			r.With(requireSuperAdmin()).Post("/deliverability/fbl", s.handleCreateFBLReport)

			// Config management — super_admin only.
			r.With(requireSuperAdmin()).Get("/config", s.handleGetConfig)
			r.With(requireSuperAdmin()).Post("/config/validate", s.handleValidateConfig)
			r.With(requireSuperAdmin()).Get("/config/diff", s.handleConfigDiff)
			r.With(requireSuperAdmin()).Post("/config/apply", s.handleConfigApply)

			// Orchestrator proxy — super_admin only.
			r.With(requireSuperAdmin()).Post("/orchestrator/plan", s.handleOrchestratorPlan)
			r.With(requireSuperAdmin()).Post("/orchestrator/apply", s.handleOrchestratorApply)
			r.With(requireSuperAdmin()).Post("/orchestrator/rollback", s.handleOrchestratorRollback)
			r.With(requireSuperAdmin()).Get("/orchestrator/status", s.handleOrchestratorStatus)
			r.With(requireSuperAdmin()).Get("/orchestrator/history", s.handleOrchestratorHistory)

			// System — super_admin only.
			r.With(requireSuperAdmin()).Get("/health/{service}", s.handleServiceHealth)
			r.With(requireSuperAdmin()).Get("/logs/{service}", s.handleServiceLogs)
			r.With(requireSuperAdmin()).Get("/metrics", s.handleMetrics)
			// Prometheus scrape endpoint — super_admin only (G-M2). External
			// scrapers pass a super_admin API-key bearer token.
			r.With(requireSuperAdmin()).Handle("/metrics/prometheus", promhttp.Handler())

			// Alerts — super_admin only.
			r.With(requireSuperAdmin()).Get("/alerts", s.handleListAlerts)
			r.With(requireSuperAdmin()).Post("/alerts/check", s.handleRunHealthCheck)

			// Backup/Restore — super_admin only.
			r.With(requireSuperAdmin()).Post("/backup/create", s.handleBackupCreate)
			r.With(requireSuperAdmin()).Post("/backup/incremental", s.handleBackupIncremental)
			r.With(requireSuperAdmin()).Get("/backup/status/{jobId}", s.handleBackupStatus)
			r.With(requireSuperAdmin()).Get("/backup/list", s.handleBackupList)
			r.With(requireSuperAdmin()).Post("/backup/restore/{id}", s.handleBackupRestore)
			r.With(requireSuperAdmin()).Get("/backup/settings", s.handleGetBackupSettings)
			r.With(requireSuperAdmin()).Put("/backup/settings", s.handleUpdateBackupSettings)

			// Cluster management — super_admin only.
			r.With(requireSuperAdmin()).Get("/cluster/status", s.handleClusterStatus)
			r.With(requireSuperAdmin()).Get("/cluster/nodes", s.handleListClusterNodes)
			r.With(requireSuperAdmin()).Delete("/cluster/nodes/{nodeID}", s.handleRemoveClusterNode)
			r.With(requireSuperAdmin()).Post("/cluster/rolling-update", s.handleClusterRollingUpdate)
			r.With(requireSuperAdmin()).Post("/cluster/rolling-rollback", s.handleClusterRollingRollback)
			r.With(requireSuperAdmin()).Get("/cluster/operations", s.handleListClusterOperations)
			r.With(requireSuperAdmin()).Get("/cluster/operations/{operationID}", s.handleGetClusterOperation)
		})
	})

	// SCIM 2.0 provisioning (Enterprise). Top-level group, sibling to /api/v1,
	// so it owns its own application/scim+json media type and SCIM error shape
	// rather than the Vectis JSON envelope. Auth is a Bearer scim_ token (not a
	// session); the Enterprise feature gate denies non-Enterprise installs with
	// a SCIM-shaped 403. See internal/scim, scim_middleware.go, handle_scim.go.
	r.Route("/scim/v2", func(r chi.Router) {
		r.Use(scimAuthMiddleware(s.scimTokens, s.logger))
		r.Use(s.scimFeatureGate)

		r.Get("/ServiceProviderConfig", s.handleSCIMServiceProviderConfig)
		r.Get("/ResourceTypes", s.handleSCIMResourceTypes)
		r.Get("/Schemas", s.handleSCIMSchemas)

		r.Post("/Users", s.handleSCIMCreateUser)
		r.Get("/Users", s.handleSCIMListUsers)
		r.Get("/Users/{id}", s.handleSCIMGetUser)
		r.Put("/Users/{id}", s.handleSCIMReplaceUser)
		r.Patch("/Users/{id}", s.handleSCIMPatchUser)
		r.Delete("/Users/{id}", s.handleSCIMDeleteUser)
	})

	// Serve admin UI static files if WebDir is configured.
	if s.webDir != "" {
		if _, err := os.Stat(s.webDir); err == nil {
			fileServer := http.FileServer(http.Dir(s.webDir))
			r.Get("/assets/*", func(w http.ResponseWriter, r *http.Request) {
				w.Header().Del("Content-Type") // let FileServer set it
				fileServer.ServeHTTP(w, r)
			})
			// SPA fallback: serve index.html for all non-API, non-asset routes.
			r.NotFound(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/api/") {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(404)
					w.Write([]byte(`{"error":{"code":"NOT_FOUND","message":"Endpoint not found"}}`))
					return
				}
				w.Header().Set("Content-Type", "text/html")
				indexPath := s.webDir + "/index.html"
				if data, err := fs.ReadFile(os.DirFS(s.webDir), "index.html"); err == nil {
					w.Write(data)
				} else {
					http.ServeFile(w, r, indexPath)
				}
			})
		}
	}

	return r
}
