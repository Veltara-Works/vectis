package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/logging"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/spf13/cobra"
)

var adminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Administrator account commands",
}

var adminInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create the initial admin account from secrets.yaml (idempotent)",
	Long: `Reads admin_email / admin_password from secrets.yaml and seeds the
initial admin account. If an account with that email already exists, does
nothing. If admin_password is still the default placeholder, generates a
random 16-character password and prints it to stdout.

Intended to run inside a one-shot vectis-api container on the vectis-data
network (postgres is not reachable from the host in normal installs).`,
	RunE: runAdminInit,
}

func runAdminInit(cmd *cobra.Command, args []string) error {
	configDir, _ := cmd.Flags().GetString("config-dir")

	_, secrets, err := config.LoadAll(configDir)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	logger := logging.NewLogger("warn")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	dbCfg := database.ConfigFromSecrets(
		secrets.Database.Host, secrets.Database.Port, secrets.Database.Name,
		secrets.Database.APIUser, secrets.Database.APIPassword,
	)
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: cannot connect to database: %s\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	adminRepo := repository.NewAdminRepo(pool)
	existing, _ := adminRepo.GetByEmail(ctx, secrets.API.AdminEmail)
	if existing != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "admin account %s already exists — nothing to do\n", secrets.API.AdminEmail)
		return nil
	}

	password := secrets.API.AdminPassword
	generated := false
	if password == "" || password == "CHANGE_ME_admin_password" {
		password = generateRandomPassword(16)
		generated = true
	}

	hash, err := auth.HashPassword(password)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error hashing password: %s\n", err)
		os.Exit(1)
	}

	if _, err := adminRepo.Create(ctx, repository.AdminCreate{
		Email:        secrets.API.AdminEmail,
		PasswordHash: hash,
	}); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error creating admin: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "admin_email=%s\n", secrets.API.AdminEmail)
	if generated {
		fmt.Fprintf(cmd.OutOrStdout(), "admin_password=%s\n", password)
		fmt.Fprintln(cmd.OutOrStdout(), "# password was generated — store it securely and change after first login")
	}
	return nil
}

func init() {
	adminCmd.AddCommand(adminInitCmd)
	RootCmd.AddCommand(adminCmd)
}
