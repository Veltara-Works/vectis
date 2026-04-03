package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/api"
	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/logging"
)

const version = "v0.5.0-dev"

// RootCmd is the top-level Cobra command for the Vectis CLI.
var RootCmd = &cobra.Command{
	Use:     "vectis",
	Short:   "Vectis Mail Server",
	Long:    "Vectis Mail Server — a modern, multi-tenant email platform.",
	Version: version,
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the Vectis API server",
	RunE:  runServe,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version of Vectis",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("vectis %s\n", version)
	},
}

func runServe(cmd *cobra.Command, args []string) error {
	configDir, _ := cmd.Flags().GetString("config-dir")

	cfg, secrets, err := config.LoadAll(configDir)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	logger := logging.NewLogger(cfg.Logging.Level)

	// Connect to Postgres.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbCfg := database.ConfigFromSecrets(
		secrets.Database.Host, secrets.Database.Port, secrets.Database.Name,
		secrets.Database.APIUser, secrets.Database.APIPassword,
	)
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: database connection failed: %s\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Run pending migrations.
	if err := database.RunMigrations(dbCfg.DSN(), logger); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: migration failed: %s\n", err)
		os.Exit(1)
	}

	// Connect to Valkey.
	vkCfg := database.ValkeyConfig{
		Host: secrets.Valkey.Host, Port: secrets.Valkey.Port, Password: secrets.Valkey.Password,
	}
	vk, err := database.NewValkeyClient(vkCfg, logger)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: valkey connection failed: %s\n", err)
		os.Exit(1)
	}
	defer vk.Close()

	// Start API server.
	webDir, _ := cmd.Flags().GetString("web-dir")
	orchURL := "http://orchestrator:8081"
	if envURL := os.Getenv("VECTIS_ORCHESTRATOR_URL"); envURL != "" {
		orchURL = envURL
	}

	srv := api.New(pool, vk, api.Config{
		ListenAddr:        cfg.Admin.ListenAddr,
		SessionTTL:        cfg.Admin.SessionTTLHours,
		CookieSecret:      secrets.API.Secret,
		Hostname:          cfg.Hostname,
		DKIMBasePath:      secrets.DKIM.KeyBasePath,
		WebDir:            webDir,
		GenDir:            "/var/vectis/generated",
		VectisCfg:         cfg,
		VectisSecrets:     secrets,
		OrchestratorURL:   orchURL,
		OrchestratorToken: secrets.Orchestrator.Token,
	}, logger)

	// Start background services.
	srv.StartMonitor()
	srv.StartAuditPruner()

	// Graceful shutdown.
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start() }()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case sig := <-quit:
		logger.Info("received shutdown signal", "signal", sig.String())
	case err := <-errCh:
		if err != nil {
			return err
		}
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()
	return srv.Shutdown(shutdownCtx)
}

// isQuiet returns true if the --quiet flag is set.
func isQuiet(cmd *cobra.Command) bool {
	q, _ := cmd.Flags().GetBool("quiet")
	return q
}

// isVerbose returns true if the --verbose flag is set.
func isVerbose(cmd *cobra.Command) bool {
	v, _ := cmd.Flags().GetBool("verbose")
	return v
}

func init() {
	// Global persistent flags available to all subcommands.
	RootCmd.PersistentFlags().String("config-dir", "/etc/vectis/", "Path to configuration directory")
	RootCmd.PersistentFlags().Bool("json", false, "Output in JSON format")
	RootCmd.PersistentFlags().Bool("quiet", false, "Suppress non-essential output")
	RootCmd.PersistentFlags().Bool("verbose", false, "Enable verbose output")

	serveCmd.Flags().String("web-dir", "", "Path to admin UI static files (serves UI alongside API)")

	// Register subcommands.
	RootCmd.AddCommand(serveCmd)
	RootCmd.AddCommand(versionCmd)
}
