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
	"github.com/valkey-io/valkey-go"

	"github.com/Veltara-Works/vectis/internal/audit"
	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/backup"
	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/monitor"
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
	db           *pgxpool.Pool
	vk           valkey.Client
	sessions     *auth.SessionManager
	hostname     string
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
	audit        *repository.AuditRepo
	alerts       *repository.AlertRepo

	// TOTP
	totpManager *auth.TOTPManager

	// Background services
	monitor      *monitor.Monitor
	auditPruner  *audit.Pruner
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
}

// New creates a new API server with all routes registered.
func New(db *pgxpool.Pool, vk valkey.Client, cfg Config, logger *slog.Logger) *Server {
	s := &Server{
		logger:       logger,
		db:           db,
		vk:           vk,
		sessions:     auth.NewSessionManager(db, vk, cfg.SessionTTL, cfg.CookieSecret),
		hostname:     cfg.Hostname,
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
		audit:        repository.NewAuditRepo(db),
		alerts:       repository.NewAlertRepo(db),
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
	alerter := monitor.NewAlerter(
		s.alerts,
		s.cfg.Alerts.Email,
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

// Shutdown gracefully stops the server.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down API server")
	s.StopMonitor()
	s.StopAuditPruner()
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

	return backup.NewManager(s.db, s.logger.With("component", "backup"), cfg)
}

func (s *Server) buildRouter() chi.Router {
	r := chi.NewRouter()

	// Global middleware.
	r.Use(chimw.RealIP)
	r.Use(requestIDMiddleware)
	r.Use(s.loggingMiddleware)
	r.Use(chimw.Recoverer)

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(jsonContentType)
		// Public endpoints.
		r.Get("/health", s.handleHealth)
		r.Get("/version", s.handleVersion)
		r.With(chimw.Throttle(5)).Post("/auth/login", s.handleLogin)

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
			r.With(requireSuperAdmin()).Delete("/admins/{adminID}", s.handleDeleteAdmin)

			// Audit log — all roles (domain_admin filtered in handler).
			r.Get("/audit", s.handleListAudit)

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
			r.With(requireSuperAdmin()).Get("/backup/status/{jobId}", s.handleBackupStatus)
			r.With(requireSuperAdmin()).Get("/backup/list", s.handleBackupList)
			r.With(requireSuperAdmin()).Post("/backup/restore/{id}", s.handleBackupRestore)
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
