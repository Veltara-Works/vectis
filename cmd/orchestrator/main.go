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
	"github.com/Veltara-Works/vectis/internal/engine"
	"github.com/Veltara-Works/vectis/internal/orchestrator"
	"github.com/Veltara-Works/vectis/internal/repository"
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
	// rc48 reworks the in-progress + self-upgrade banner copy to proper
	// English prose (state-aware phrasing, no redundant "step: apply"
	// tuple), drops the "Current step" line under the State badge for the
	// same reason, and normalises user-facing language on "update" (not
	// "upgrade"). The step field was the same value as state anyway.
	// rc49 is the human-UI target for rc48's copy changes, same pattern
	// as rc47 being the target for rc46's UX fixes — the rc48 bundle only
	// starts being served after the api container swap during rc47→rc48,
	// so the user won't see the new banner prose until they Apply again
	// with the rc48 bundle already loaded. rc48→rc49 is that run.
	// rc50 fixes the last GA wart from the rc49 walkthrough: the green
	// "Update started…" banner set on the Apply 202 was never cleared
	// by the auto-refresh loop, so it lingered visibly stale long after
	// the History row had flipped to completed. The fix wires a small
	// applyTracking state machine (awaiting → in-flight → idle) into
	// the existing poll, promoting the banner to "Update completed
	// successfully." once the orchestrator settles back to idle with
	// the self-upgrade window cleared.
	// rc51 is the human-UI test target for rc50's banner-clear fix.
	// rc50→rc51 is the only walkthrough that exercises the new logic
	// against a real upgrade — rc49→rc50 necessarily ran under the
	// rc49 bundle, which still has the stale banner bug. v0.1.0 is
	// cut from this commit if the rc51 walkthrough lands clean.
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

	// Wire up the compose generator that Phase 3.5 of Apply uses to
	// regenerate /etc/vectis/docker-compose.yml from the embedded templates.
	// Closes over configDir/dbPool so the orchestrator package itself stays
	// decoupled from internal/engine + internal/repository (deferred-
	// items.md §10).
	//
	// IMPORTANT: cfg + secrets are reloaded from disk on every invocation,
	// not captured at startup. The operator's edits to config.yaml (e.g.
	// flipping clamav.profile) must take effect on the next Plan/Apply
	// without an orchestrator restart. Caught on prod 2026-05-05: a stale
	// captured cfg made Phase 3.5 render compose with the previous-startup
	// profile value, so config-driven structural changes silently no-op'd.
	domainRepo := repository.NewDomainRepo(dbPool)
	orch.SetComposeGenerator(func(ctx context.Context, releaseTag string) ([]byte, error) {
		freshCfg, freshSecrets, err := config.LoadAll(configDir)
		if err != nil {
			return nil, fmt.Errorf("reload config: %w", err)
		}
		domains, err := domainRepo.List(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("list domains: %w", err)
		}
		data := engine.NewTemplateData(freshCfg, freshSecrets, domains)
		if releaseTag != "" {
			data.Version = releaseTag
		}
		files, err := engine.Generate(data)
		if err != nil {
			return nil, fmt.Errorf("render templates: %w", err)
		}
		for _, f := range files {
			if f.RelPath == "docker-compose.yml" {
				return f.Content, nil
			}
		}
		return nil, fmt.Errorf("docker-compose.yml not present in rendered templates")
	})

	// Wire up the per-service config generator that Apply Phase 3.6 and
	// startup self-heal both use to reconcile structural drift across all
	// rendered service configs (postfix/dovecot/rspamd/traefik/clamav/...)
	// under cfg.GeneratedConfigDir. Same fresh-load semantics as compose
	// generator above — config.yaml edits land on the next call.
	orch.SetConfigGenerator(func(ctx context.Context, releaseTag string) ([]orchestrator.ConfigFile, error) {
		freshCfg, freshSecrets, err := config.LoadAll(configDir)
		if err != nil {
			return nil, fmt.Errorf("reload config: %w", err)
		}
		domains, err := domainRepo.List(ctx, nil)
		if err != nil {
			return nil, fmt.Errorf("list domains: %w", err)
		}
		data := engine.NewTemplateData(freshCfg, freshSecrets, domains)
		if releaseTag != "" {
			data.Version = releaseTag
		}
		files, err := engine.Generate(data)
		if err != nil {
			return nil, fmt.Errorf("render templates: %w", err)
		}
		out := make([]orchestrator.ConfigFile, 0, len(files))
		for _, f := range files {
			// Compose lives at /etc/vectis and is owned by ComposeGenerator.
			if f.RelPath == "docker-compose.yml" {
				continue
			}
			out = append(out, orchestrator.ConfigFile{
				RelPath: f.RelPath,
				Content: f.Content,
				Mode:    f.Mode,
			})
		}
		return out, nil
	})

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

	// Self-heal compose on a detected version transition. Closes the
	// cross-version gap left by §10's Phase-3.5 regen design: if the
	// previous boot was on an older orchestrator binary, the on-disk
	// compose may be missing structural template additions that ship in
	// this version (new bind mounts, new services, etc.). Best-effort —
	// failures are logged but never block startup. Called BEFORE server
	// start so a fresh-replaced orchestrator is fully reconciled before
	// it accepts API requests.
	healCtx, healCancel := context.WithTimeout(ctx, 120*time.Second)
	orch.SelfHealComposeOnVersionTransition(healCtx, version.Version)
	healCancel()

	// Start server in a goroutine.
	errCh := make(chan error, 1)
	go func() {
		errCh <- srv.Start()
	}()

	// -----------------------------------------------------------------------
	// Background: network drift watchdog
	// -----------------------------------------------------------------------
	// Periodically reconciles each Vectis container's actual Docker network
	// attachments against its compose declaration. Self-heals by reconnecting
	// any missing internal network. Driven by the prod 2026-04-27 incident
	// where `docker compose run` silently disconnected vectis-api from
	// vectis_vectis-data and never re-attached. See deferred-items.md §11.
	watchdogDocker := orchestrator.NewDockerManager(orchCfg, logger.With("component", "docker"))
	go orchestrator.RunNetworkWatchdog(ctx, watchdogDocker, 60*time.Second, logger)

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
