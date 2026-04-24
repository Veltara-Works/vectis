package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/orchestrator"
	vectistls "github.com/Veltara-Works/vectis/internal/tls"
	"github.com/Veltara-Works/vectis/internal/version"
)

const (
	configDir  = "/etc/vectis"
	listenAddr = ":8081"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))
	slog.SetDefault(logger)

	if err := run(logger); err != nil {
		logger.Error("orchestrator exiting with error", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Version log is the first useful signal in `docker logs vectis-orchestrator`
	// — especially after an Apply-driven upgrade when the operator wants to
	// confirm the orchestrator container was actually replaced by the rc36+
	// helper (GA Blocker #9 fix). Pair this with `docker inspect vectis-apply-helper*`
	// if the replacement appears stuck. On rc40+ the helper also handles
	// installs without clamav / other optional services cleanly. Validated
	// end-to-end by the rc40→rc41 walkthrough on sysadmin1001 (2026-04-24).
	// rc44 is the GA-gate walkthrough target — a clean rc43→rc44 Apply via
	// the admin UI is the last checkbox before tagging v0.1.0.
	// rc45 exists so a human operator can drive the rc44→rc45 Apply by hand
	// in the admin UI (Updates page, Dashboard banner, Bad-Gateway window UX).
	// The rc43→rc44 walkthrough was API-only; rc45 is the human-eyes pass
	// before GA is cut from the same commit.
	// rc46 fixes what the rc45 UI walkthrough surfaced: the Updates page
	// polled only during the self_upgrade window — which never started,
	// because self_upgrade_until is only written ~60s into Apply and
	// nothing else re-fetched status. Result: History row stuck at
	// "running" and no countdown banner ever appeared. rc46 broadens the
	// poll to any non-terminal state, adds an in-progress banner with
	// current_step, and renders plan_summary as a readable one-liner.
	// rc47 is the human-UI test target for rc46's own fixes — an Apply
	// driven from the rc46 bundle (already loaded in the browser) is the
	// only way to see the new in-progress banner and auto-refreshing
	// history row in action, since rc45→rc46 necessarily ran under the
	// old rc45 UI. rc47 also ships a small copy tweak to the Plan success
	// message so it tells the user what to do next.
	logger.Info("orchestrator starting", "version", version.Version)

	// -----------------------------------------------------------------------
	// Load configuration
	// -----------------------------------------------------------------------
	logger.Info("loading configuration", "config_dir", configDir)

	cfg, secrets, err := config.LoadAll(configDir)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// Set log level from config.
	var logLevel slog.Level
	switch cfg.Logging.Level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}
	logger = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// -----------------------------------------------------------------------
	// Connect to Postgres
	// -----------------------------------------------------------------------
	pgDSN := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		secrets.Database.APIUser,
		secrets.Database.APIPassword,
		secrets.Database.Host,
		secrets.Database.Port,
		secrets.Database.Name,
	)

	logger.Info("connecting to postgres", "host", secrets.Database.Host, "port", secrets.Database.Port)
	dbPool, err := pgxpool.New(ctx, pgDSN)
	if err != nil {
		return fmt.Errorf("connect to postgres: %w", err)
	}
	defer dbPool.Close()

	if err := dbPool.Ping(ctx); err != nil {
		return fmt.Errorf("ping postgres: %w", err)
	}
	logger.Info("postgres connected")

	// -----------------------------------------------------------------------
	// Connect to Valkey
	// -----------------------------------------------------------------------
	vkAddr := fmt.Sprintf("%s:%d", secrets.Valkey.Host, secrets.Valkey.Port)
	logger.Info("connecting to valkey", "addr", vkAddr)

	vkClient, err := valkey.NewClient(valkey.ClientOption{
		InitAddress: []string{vkAddr},
		Password:    secrets.Valkey.Password,
	})
	if err != nil {
		return fmt.Errorf("connect to valkey: %w", err)
	}
	defer vkClient.Close()
	logger.Info("valkey connected")

	// -----------------------------------------------------------------------
	// Initialise orchestrator
	// -----------------------------------------------------------------------
	orchCfg := orchestrator.DefaultConfig()
	orchCfg.BearerToken = secrets.Orchestrator.Token
	orchCfg.DBHost = secrets.Database.Host
	orchCfg.DBPort = secrets.Database.Port
	orchCfg.DBName = secrets.Database.Name
	orchCfg.DBUser = secrets.Database.APIUser
	orchCfg.DBPassword = secrets.Database.APIPassword

	// VECTIS_ORCH_COMPOSE_PATHS lets the operator point the orchestrator at the
	// actually-deployed compose files. Useful when prod runs from a two-file
	// setup (e.g. /opt/vectis/docker-compose.yml + docker-compose.mail.yml) that
	// differs from the config-engine-generated /etc/vectis/docker-compose.yml.
	// Colon-separated list, order matters (matches docker compose -f precedence).
	if raw := os.Getenv("VECTIS_ORCH_COMPOSE_PATHS"); raw != "" {
		parts := strings.Split(raw, ":")
		paths := make([]string, 0, len(parts))
		for _, p := range parts {
			if p = strings.TrimSpace(p); p != "" {
				paths = append(paths, p)
			}
		}
		if len(paths) > 0 {
			orchCfg.ComposePaths = paths
			logger.Info("overriding compose paths from env", "paths", paths)
		}
	}

	// VECTIS_ORCH_RELEASE_CHANNEL_URL lets the operator point the Plan step
	// at a custom release manifest. Useful for airgapped installs pointing at
	// an internal mirror, or tests pointing at a local httptest server. An
	// empty value disables release-channel discovery entirely (Plan then only
	// reports local compose-vs-running drift).
	if raw := os.Getenv("VECTIS_ORCH_RELEASE_CHANNEL_URL"); raw != "" {
		orchCfg.ReleaseChannelURL = strings.TrimSpace(raw)
		logger.Info("overriding release channel URL from env", "url", orchCfg.ReleaseChannelURL)
	}

	orch, err := orchestrator.New(ctx, dbPool, vkClient, orchCfg, logger.With("component", "orchestrator"))
	if err != nil {
		return fmt.Errorf("init orchestrator: %w", err)
	}
	logger.Info("orchestrator initialised", "state", orch.State())

	// -----------------------------------------------------------------------
	// Start HTTP server
	// -----------------------------------------------------------------------
	srvCfg := orchestrator.ServerConfig{
		ListenAddr: listenAddr,
		Token:      secrets.Orchestrator.Token,
	}

	// Enable mTLS if certificate directory is configured.
	if secrets.Orchestrator.MTLSCertDir != "" {
		tlsCfg, err := vectistls.NewServerTLSConfig(secrets.Orchestrator.MTLSCertDir)
		if err != nil {
			logger.Warn("failed to load mTLS certs, falling back to bearer token", "error", err)
		} else {
			srvCfg.TLSConfig = tlsCfg
			logger.Info("orchestrator server using mTLS", "cert_dir", secrets.Orchestrator.MTLSCertDir)
		}
	}

	srv := orchestrator.NewServer(orch, srvCfg, logger.With("component", "http"))

	// Start server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// -----------------------------------------------------------------------
	// Graceful shutdown
	// -----------------------------------------------------------------------
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-sigCh:
		logger.Info("received signal, shutting down", "signal", sig)
	case err := <-errCh:
		return fmt.Errorf("server error: %w", err)
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown: %w", err)
	}

	logger.Info("orchestrator shut down cleanly")
	return nil
}
