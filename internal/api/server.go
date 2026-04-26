package api

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
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
	"github.com/Veltara-Works/vectis/internal/mail"
	"github.com/Veltara-Works/vectis/internal/mail/postfixlog"
	vectismetrics "github.com/Veltara-Works/vectis/internal/metrics"
	"github.com/Veltara-Works/vectis/internal/monitor"
	"github.com/Veltara-Works/vectis/internal/validonx"
	"github.com/Veltara-Works/vectis/internal/orchestrator"
	"github.com/Veltara-Works/vectis/internal/repository"
	vectistls "github.com/Veltara-Works/vectis/internal/tls"
)

// Server is the Vectis API server.
type Server struct {
	router     chi.Router
	httpServer *http.Server
	logger     *slog.Logger

	// Dependencies
	db            *pgxpool.Pool
	vk            valkey.Client
	sessions      *auth.SessionManager
	hostname      string
	internalToken string // shared secret for service-to-service calls (Postfix → API)
	dkimBasePath string
	webDir       string
	genDir       string // directory for generated config files
	cfg          *config.VectisConfig
	secrets      *config.VectisSecrets
	orchClient   *orchestrator.Client

	// Repositories
	domains      *repository.DomainRepo
	mailboxes    *repository.MailboxRepo
	aliases      *repository.AliasRepo
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

	// Notifications
	notifications *mail.NotificationSender

	// TOTP
	totpManager *auth.TOTPManager

	// OIDC
	oidcManager *auth.OIDCManager

	// Mail sending, webhooks, abuse detection
	mailSender        *mail.Sender
	webhookDispatcher *mail.WebhookDispatcher
	abuseDetector     *mail.AbuseDetector
	postfixTailer     *postfixlog.Tailer

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
	monitor        *monitor.Monitor
	auditPruner    *audit.Pruner
	sessionCleaner *auth.SessionCleaner
	usageReporter  *validonx.UsageReporter
	// featureGate is always non-nil. When ValidonX is not configured, it
	// passes through every FeatureGate(...) call (free-tier mode).
	featureGate *validonx.FeatureGateService
}

// Config holds API server configuration.
type Config struct {
	ListenAddr   string
	SessionTTL   int // hours
	CookieSecret string
	Hostname     string
	DKIMBasePath string
	WebDir            string // path to static UI files (optional)
	GenDir            string // path to generated config output directory
	VectisCfg         *config.VectisConfig
	VectisSecrets     *config.VectisSecrets
	OrchestratorURL      string // http://orchestrator:8081 or https://orchestrator:8081
	OrchestratorToken    string // bearer token for orchestrator internal API (fallback)
	OrchestratorCertDir  string // mTLS certificate directory; when set, upgrades to mTLS
	CallbackBaseURL      string // base URL for OIDC callbacks (e.g. https://mail.example.com)
	ServerIPs            []string // server IP addresses for RBL monitoring
	PostfixLogPath       string   // path to Postfix mail log for delivery/bounce event tailing; empty disables
}

// New creates a new API server with all routes registered.
func New(db *pgxpool.Pool, vk valkey.Client, cfg Config, logger *slog.Logger) *Server {
	s := &Server{
		logger:       logger,
		db:           db,
		vk:           vk,
		sessions:      auth.NewSessionManager(db, vk, cfg.SessionTTL, cfg.CookieSecret),
		hostname:      cfg.Hostname,
		internalToken: cfg.CookieSecret, // reuse API secret as internal service token
		dkimBasePath: cfg.DKIMBasePath,
		webDir:       cfg.WebDir,
		genDir:       cfg.GenDir,
		cfg:          cfg.VectisCfg,
		secrets:      cfg.VectisSecrets,
		domains:      repository.NewDomainRepo(db),
		mailboxes:    repository.NewMailboxRepo(db),
		aliases:      repository.NewAliasRepo(db),
		admins:       repository.NewAdminRepo(db),
		adminDomains: repository.NewAdminDomainRepo(db),
		apiKeys:      repository.NewAPIKeyRepo(db),
		webhooks:     repository.NewWebhookRepo(db),
		abuseEvents:  repository.NewAbuseRepo(db),
		audit:        repository.NewAuditRepo(db),
		alerts:       repository.NewAlertRepo(db),
		messages:     repository.NewMessageRepo(db),
		mailStats:    repository.NewMailStatsRepo(db),
		emailEvents:  repository.NewEmailEventRepo(db),
		ipWarmup:     repository.NewIPWarmupRepo(db),
		rblChecks:    repository.NewRBLCheckRepo(db),
		fblReports:   repository.NewFBLReportRepo(db),
		resetTokens:  repository.NewPasswordResetRepo(db),
		totpManager:  auth.NewTOTPManager(cfg.CookieSecret, cfg.Hostname),
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

	// Register Prometheus metrics collector.
	prometheus.MustRegister(vectismetrics.NewCollector(db, logger.With("component", "metrics")))

	// Initialize mail sender, notification sender, webhook dispatcher, and abuse detector.
	s.mailSender = mail.NewSender("vectis-postfix:25", cfg.Hostname, logger.With("component", "mail-sender"))
	s.notifications = mail.NewNotificationSender(s.mailSender, cfg.Hostname)
	s.webhookDispatcher = mail.NewWebhookDispatcher(s.webhooks, logger.With("component", "webhook-dispatcher"))
	s.abuseDetector = mail.NewAbuseDetector(vk, mail.DefaultAbuseConfig(), logger.With("component", "abuse-detector"))

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
	// FeatureGateService is always non-nil. When unconfigured, FeatureGate
	// passes every request through (free-tier mode), so handlers can call
	// s.featureGate.* unconditionally.
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

	alerter := monitor.NewAlerter(
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

	s.monitor = monitor.New(s.db, s.vk, alerter, monCfg, s.logger.With("component", "monitor"))
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

// StopUsageReporter stops the ValidonX usage metrics reporter.
func (s *Server) StopUsageReporter() {
	if s.usageReporter != nil {
		s.usageReporter.Stop()
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
	s.StopSessionCleaner()
	s.StopWebhookDispatcher()
	s.StopPostfixLogTailer()
	s.StopUsageReporter()
	s.StopRBLMonitor()
	s.StopWarmupManager()
	s.StopCluster()
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
		r.Handle("/metrics/prometheus", promhttp.Handler())
		r.With(chimw.Throttle(5)).Post("/auth/login", s.handleLogin)
		r.With(chimw.Throttle(3)).Post("/auth/reset-request", s.handleRequestPasswordReset)
		r.With(chimw.Throttle(3)).Post("/auth/reset-password", s.handleResetPassword)

		// Internal service-to-service endpoints (token-authenticated, not session).
		r.Post("/internal/inbound", s.handleInboundNotify)

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

		// Authenticated endpoints.
		r.Group(func(r chi.Router) {
			r.Use(s.authMiddleware)

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

			// Domains — all roles (domain_admin scoped in handlers).
			r.Get("/domains", s.handleListDomains)
			r.Get("/domains/{domainID}", s.handleGetDomain)
			r.Get("/domains/{domainID}/dkim", s.handleGetDKIM)
			r.Get("/domains/{domainID}/deliverability", s.handleDeliverability)
			// Domain mutations — admin and super_admin only.
			r.With(requireAdminOrAbove()).Post("/domains", s.handleCreateDomain)
			r.With(requireAdminOrAbove()).Patch("/domains/{domainID}", s.handleUpdateDomain)
			r.With(requireAdminOrAbove()).Delete("/domains/{domainID}", s.handleDeleteDomain)
			r.With(requireAdminOrAbove()).Post("/domains/{domainID}/dkim/generate", s.handleGenerateDKIM)
			r.With(requireAdminOrAbove()).Post("/domains/{domainID}/dkim/rotate", s.handleRotateDKIM)
			r.With(requireAdminOrAbove()).Post("/domains/{domainID}/verify", s.handleVerifyDomain)

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

			// Audit log — all roles (domain_admin filtered in handler).
			r.Get("/audit", s.handleListAudit)
			r.With(requireSuperAdmin()).Get("/audit/export", s.handleExportAudit)

			// Sieve filter management — all roles (domain scoping in handler).
			r.Get("/mailboxes/{mailboxID}/sieve", s.handleListSieveScripts)
			r.Get("/mailboxes/{mailboxID}/sieve/{scriptName}", s.handleGetSieveScript)
			r.Put("/mailboxes/{mailboxID}/sieve", s.handlePutSieveScript)
			r.Delete("/mailboxes/{mailboxID}/sieve/{scriptName}", s.handleDeleteSieveScript)

			// Log search — super_admin only.
			r.With(requireSuperAdmin()).Get("/logs/search", s.handleLogSearch)

			// Engagement tracking stats — admin and super_admin.
			r.With(requireAdminOrAbove()).Get("/tracking/stats", s.handleTrackingStats)
			r.With(requireAdminOrAbove()).Get("/tracking/messages/{messageID}", s.handleMessageEngagement)
			r.With(requireAdminOrAbove()).Get("/tracking/messages/{messageID}/events", s.handleMessageEngagementEvents)

			// Abuse detection — admin and super_admin.
			r.With(requireAdminOrAbove()).Get("/abuse/dashboard", s.handleAbuseDashboard)
			r.With(requireAdminOrAbove()).Get("/abuse/events", s.handleListAbuseEvents)
			r.With(requireAdminOrAbove()).Post("/abuse/events/{eventID}/resolve", s.handleResolveAbuseEvent)
			r.With(requireAdminOrAbove()).Post("/abuse/mailboxes/{mailboxID}/suspend", s.handleSuspendMailbox)
			r.With(requireAdminOrAbove()).Post("/abuse/mailboxes/{mailboxID}/unsuspend", s.handleUnsuspendMailbox)

			// Admin impersonation — admin and super_admin.
			r.With(requireAdminOrAbove()).Post("/mailboxes/{mailboxID}/impersonate", s.handleImpersonate)
			r.With(requireAdminOrAbove()).Delete("/mailboxes/{mailboxID}/impersonate", s.handleRevokeImpersonation)

			// Per-domain analytics — Pro feature; gated by FeatureGate.
			// Free installs (ValidonX unconfigured) pass through. Authenticated
			// users on a paying customer with active Pro license: 200.
			// Cancelled/lapsed Pro license past 30-day grace: 403 LICENSE_EXPIRED.
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

			// Alerts — super_admin only.
			r.With(requireSuperAdmin()).Get("/alerts", s.handleListAlerts)
			r.With(requireSuperAdmin()).Post("/alerts/check", s.handleRunHealthCheck)

			// Backup/Restore — super_admin only.
			r.With(requireSuperAdmin()).Post("/backup/create", s.handleBackupCreate)
			r.With(requireSuperAdmin()).Post("/backup/incremental", s.handleBackupIncremental)
			r.With(requireSuperAdmin()).Get("/backup/status/{jobId}", s.handleBackupStatus)
			r.With(requireSuperAdmin()).Get("/backup/list", s.handleBackupList)
			r.With(requireSuperAdmin()).Post("/backup/restore/{id}", s.handleBackupRestore)

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
