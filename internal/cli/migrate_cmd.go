package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/logging"
	"github.com/spf13/cobra"
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "Database migration commands",
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply all pending migrations",
	RunE:  runMigrateUp,
}

var migrateStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current migration version",
	RunE:  runMigrateStatus,
}

func runMigrateUp(cmd *cobra.Command, args []string) error {
	secrets, err := loadSecrets(cmd)
	if err != nil {
		return err
	}

	logger := logging.NewLogger("info")
	dbCfg := database.ConfigFromSecrets(
		secrets.Database.Host,
		secrets.Database.Port,
		secrets.Database.Name,
		secrets.Database.APIUser,
		secrets.Database.APIPassword,
	)

	// Verify connectivity first.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: cannot connect to database: %s\n", err)
		os.Exit(1)
	}
	pool.Close()

	if err := database.RunMigrations(dbCfg.DSN(), logger); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Migrations applied successfully")
	return nil
}

func runMigrateStatus(cmd *cobra.Command, args []string) error {
	secrets, err := loadSecrets(cmd)
	if err != nil {
		return err
	}

	dbCfg := database.ConfigFromSecrets(
		secrets.Database.Host,
		secrets.Database.Port,
		secrets.Database.Name,
		secrets.Database.APIUser,
		secrets.Database.APIPassword,
	)

	version, dirty, err := database.MigrationStatus(dbCfg.DSN())
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Version: %d\nDirty:   %t\n", version, dirty)
	return nil
}

func loadSecrets(cmd *cobra.Command) (*config.VectisSecrets, error) {
	configDir, err := cmd.Flags().GetString("config-dir")
	if err != nil {
		return nil, err
	}

	secrets, err := config.LoadSecrets(configDir + "/secrets.yaml")
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	return secrets, nil
}

func init() {
	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateStatusCmd)
	RootCmd.AddCommand(migrateCmd)
}
