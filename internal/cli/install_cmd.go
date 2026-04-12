package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/engine"
	"github.com/Veltara-Works/vectis/internal/logging"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/spf13/cobra"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Vectis on a fresh host",
	Long: `Performs a full installation: generates configs, pulls images,
starts containers, runs migrations, and creates the initial admin account.

Requires config.yaml and secrets.yaml in the config directory.`,
	RunE: runInstall,
}

func runInstall(cmd *cobra.Command, args []string) error {
	configDir, _ := cmd.Flags().GetString("config-dir")

	step := 0
	totalSteps := 10
	printStep := func(msg string) {
		step++
		fmt.Fprintf(cmd.OutOrStdout(), "[%d/%d] %s...", step, totalSteps, msg)
	}
	done := func() { fmt.Fprintln(cmd.OutOrStdout(), " done") }

	// Step 1: Load and validate config
	printStep("Validating configuration")
	cfg, secrets, err := config.LoadAll(configDir)
	if err != nil {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.ErrOrStderr(), "\nError: %s\n", err)
		os.Exit(1)
	}
	done()

	// Step 2: Generate secrets if they're still defaults
	printStep("Checking secrets")
	if secrets.API.Secret == "CHANGE_ME_at_least_32_characters_long_random_string" {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.ErrOrStderr(), "\nError: secrets.yaml contains default values. Generate real secrets before installing.")
		fmt.Fprintln(cmd.ErrOrStderr(), "Tip: Use 'openssl rand -hex 32' to generate random values.")
		os.Exit(1)
	}
	done()

	// Step 3: Generate config files
	printStep("Generating service configurations")
	genDir, _ := cmd.Flags().GetString("output")
	if genDir == "" {
		genDir = "/var/vectis/generated"
	}
	if err := os.MkdirAll(genDir, 0755); err != nil {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.ErrOrStderr(), "\nError creating output directory: %s\n", err)
		os.Exit(1)
	}

	// No domains yet for fresh install
	data := engine.NewTemplateData(cfg, secrets, nil)
	files, err := engine.Generate(data)
	if err != nil {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.ErrOrStderr(), "\nError generating configs: %s\n", err)
		os.Exit(1)
	}
	if err := engine.WriteFiles(genDir, files); err != nil {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.ErrOrStderr(), "\nError writing configs: %s\n", err)
		os.Exit(1)
	}
	if err := engine.WriteSecrets(filepath.Join(genDir, "secrets"), data); err != nil {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.ErrOrStderr(), "\nError writing Docker secrets: %s\n", err)
		os.Exit(1)
	}
	done()

	// Step 4: Create runtime directories and configure Docker IPv6
	printStep("Creating runtime directories")
	for _, dir := range []string{
		"/var/vectis/mail",
		"/var/vectis/dkim",
		"/var/vectis/backups",
		"/var/vectis/snapshots",
		"/var/vectis/certs",
	} {
		os.MkdirAll(dir, 0755)
	}

	// Configure Docker daemon for IPv6 support (Spec G.7) if not already configured.
	daemonJSON := "/etc/docker/daemon.json"
	if _, err := os.Stat(daemonJSON); os.IsNotExist(err) {
		ipv6Config := []byte(`{
  "ipv6": true,
  "fixed-cidr-v6": "fd00::/80",
  "experimental": true,
  "ip6tables": true
}
`)
		os.MkdirAll("/etc/docker", 0755)
		if writeErr := os.WriteFile(daemonJSON, ipv6Config, 0644); writeErr != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "\nWarning: could not write %s: %s\n", daemonJSON, writeErr)
		}
	}
	done()

	// Step 5: Install and configure Fail2ban (host-level brute-force protection)
	printStep("Configuring Fail2ban")
	configureFail2ban(cmd)
	done()

	// Step 6: Connect to database and run migrations
	printStep("Running database migrations")
	logger := logging.NewLogger("warn")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	dbCfg := database.ConfigFromSecrets(
		secrets.Database.Host, secrets.Database.Port, secrets.Database.Name,
		secrets.Database.APIUser, secrets.Database.APIPassword,
	)
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.ErrOrStderr(), "\nError: cannot connect to database: %s\n", err)
		fmt.Fprintln(cmd.ErrOrStderr(), "Ensure Postgres is running: docker compose up -d postgres")
		os.Exit(1)
	}
	defer pool.Close()

	if err := database.RunMigrations(dbCfg.DSN(), logger); err != nil {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.ErrOrStderr(), "\nError: migration failed: %s\n", err)
		os.Exit(1)
	}
	done()

	// Step 6: Create initial admin account
	printStep("Creating initial admin account")
	adminRepo := repository.NewAdminRepo(pool)

	existing, _ := adminRepo.GetByEmail(ctx, secrets.API.AdminEmail)
	adminPassword := secrets.API.AdminPassword

	if existing == nil {
		// Generate a random password if the secrets still has the default
		if adminPassword == "CHANGE_ME_admin_password" {
			adminPassword = generateRandomPassword(16)
		}

		hash, err := auth.HashPassword(adminPassword)
		if err != nil {
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintf(cmd.ErrOrStderr(), "\nError hashing admin password: %s\n", err)
			os.Exit(1)
		}

		_, err = adminRepo.Create(ctx, repository.AdminCreate{
			Email:        secrets.API.AdminEmail,
			PasswordHash: hash,
		})
		if err != nil {
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintf(cmd.ErrOrStderr(), "\nError creating admin: %s\n", err)
			os.Exit(1)
		}
	}
	done()

	// Step 7: Write generated docker-compose.yml
	printStep("Writing docker-compose.yml")
	composeSrc := filepath.Join(genDir, "docker-compose.yml")
	composeDst := filepath.Join(filepath.Dir(configDir), "docker-compose.yml")
	if composeDst == "/docker-compose.yml" {
		composeDst = "/opt/vectis/docker-compose.production.yml"
	}
	composeContent, err := os.ReadFile(composeSrc)
	if err == nil {
		os.WriteFile(composeDst, composeContent, 0644)
	}
	done()

	// Step 8: Pull container images
	printStep("Pulling container images")
	pullCmd := exec.Command("docker", "compose", "-f", composeDst, "pull")
	pullCmd.Stdout = os.Stdout
	pullCmd.Stderr = os.Stderr
	if err := pullCmd.Run(); err != nil {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.ErrOrStderr(), "\nWarning: failed to pull images: %s\n", err)
		fmt.Fprintln(cmd.ErrOrStderr(), "You can pull manually: docker compose -f "+composeDst+" pull")
	}
	done()

	// Step 9: Start services
	printStep("Starting services")
	upCmd := exec.Command("docker", "compose", "-f", composeDst, "up", "-d")
	upCmd.Stdout = os.Stdout
	upCmd.Stderr = os.Stderr
	if err := upCmd.Run(); err != nil {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.ErrOrStderr(), "\nWarning: failed to start services: %s\n", err)
		fmt.Fprintln(cmd.ErrOrStderr(), "You can start manually: docker compose -f "+composeDst+" up -d")
	}
	done()

	// Print success banner
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "═══════════════════════════════════════════")
	fmt.Fprintln(cmd.OutOrStdout(), "  Vectis is ready!")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "  Admin URL:   https://%s/admin\n", cfg.Hostname)
	fmt.Fprintf(cmd.OutOrStdout(), "  Admin email: %s\n", secrets.API.AdminEmail)
	if existing == nil {
		fmt.Fprintf(cmd.OutOrStdout(), "  Password:    %s\n", adminPassword)
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), "  IMPORTANT: Change this password immediately.")
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "  (admin account already exists)")
	}
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "  Next steps:")
	fmt.Fprintln(cmd.OutOrStdout(), "  1. Log in to the admin panel")
	fmt.Fprintln(cmd.OutOrStdout(), "  2. Add your DNS records (shown in Deliverability section)")
	fmt.Fprintln(cmd.OutOrStdout(), "  3. Create your first domain and mailbox")
	fmt.Fprintln(cmd.OutOrStdout(), "═══════════════════════════════════════════")

	return nil
}

// configureFail2ban installs and configures Fail2ban with jails for SSH and
// Postfix SASL brute-force protection. This is a host-level security measure
// per Architecture v1.4 §4.
func configureFail2ban(cmd *cobra.Command) {
	// Check if fail2ban is installed.
	if _, err := exec.LookPath("fail2ban-client"); err != nil {
		// Try to install it.
		installCmd := exec.Command("apt-get", "install", "-y", "-qq", "fail2ban")
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		if err := installCmd.Run(); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "\nWarning: could not install fail2ban: %s\n", err)
			return
		}
	}

	// Write Vectis-specific jail configuration.
	jailConfig := `# Vectis Mail Server — Fail2ban jail configuration
# Protects SSH and SMTP from brute-force attacks

[sshd]
enabled  = true
port     = ssh
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 5
bantime  = 3600
findtime = 600

[postfix-sasl]
enabled  = true
port     = smtp,465,submission
filter   = postfix[mode=auth]
logpath  = /var/lib/docker/containers/*vectis-postfix*/*-json.log
maxretry = 5
bantime  = 3600
findtime = 600
`
	jailPath := "/etc/fail2ban/jail.d/vectis.conf"
	if err := os.MkdirAll("/etc/fail2ban/jail.d", 0755); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "\nWarning: could not create fail2ban directory: %s\n", err)
		return
	}
	if err := os.WriteFile(jailPath, []byte(jailConfig), 0644); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "\nWarning: could not write fail2ban config: %s\n", err)
		return
	}

	// Restart fail2ban to apply.
	restartCmd := exec.Command("systemctl", "restart", "fail2ban")
	if err := restartCmd.Run(); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "\nWarning: could not restart fail2ban: %s\n", err)
	}
}

func generateRandomPassword(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return hex.EncodeToString(b)[:length]
}

func init() {
	installCmd.Flags().StringP("output", "o", "/var/vectis/generated", "Output directory for generated configs")
	RootCmd.AddCommand(installCmd)
}
