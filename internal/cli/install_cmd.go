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
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

var installCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Vectis on a fresh host",
	Long: `Installs Vectis end-to-end on a host that already has Docker.

Reads config.yaml and secrets.yaml from --config-dir (default /etc/vectis),
renders the service templates, brings Postgres up, runs database migrations,
seeds the initial admin account, then starts the rest of the stack.

This command is non-interactive: edit the config files first, then run it.
The bundled install.sh seeds both files with sensible defaults and random
secrets — only 'hostname' and 'tls.email' in config.yaml typically need
manual editing before running.`,
	RunE: runInstall,
}

func runInstall(cmd *cobra.Command, args []string) error {
	configDir, _ := cmd.Flags().GetString("config-dir")

	step := 0
	totalSteps := 11
	printStep := func(msg string) {
		step++
		fmt.Fprintf(cmd.OutOrStdout(), "[%d/%d] %s...", step, totalSteps, msg)
	}
	done := func() { fmt.Fprintln(cmd.OutOrStdout(), " done") }
	fail := func(format string, a ...any) {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintf(cmd.ErrOrStderr(), "\nError: "+format+"\n", a...)
		os.Exit(1)
	}

	// Step 1: Load and validate config
	printStep("Validating configuration")
	cfg, secrets, err := config.LoadAll(configDir)
	if err != nil {
		fail("%s", err)
	}
	done()

	// Step 2: Reject default-value secrets
	printStep("Checking secrets")
	if secrets.API.Secret == "CHANGE_ME_at_least_32_characters_long_random_string" {
		fail("secrets.yaml contains default values. Generate real secrets before installing.\nTip: install.sh seeds these for you on first download; otherwise use 'openssl rand -hex 32'.")
	}
	if secrets.Database.SuperuserPassword == "" || secrets.Database.SuperuserPassword == "CHANGE_ME_superuser_password" {
		fail("database.superuser_password is unset. Re-run install.sh, or set a value before installing.")
	}
	done()

	// Step 3: Render service configurations + docker-compose
	printStep("Generating service configurations")
	genDir, _ := cmd.Flags().GetString("output")
	if genDir == "" {
		genDir = "/var/vectis/generated"
	}
	if err := os.MkdirAll(genDir, 0755); err != nil {
		fail("creating output directory: %s", err)
	}

	data := engine.NewTemplateData(cfg, secrets, nil) // no domains yet on fresh install
	files, err := engine.Generate(data)
	if err != nil {
		fail("generating configs: %s", err)
	}
	if err := engine.WriteFiles(genDir, files); err != nil {
		fail("writing configs: %s", err)
	}
	if err := engine.WriteSecrets(filepath.Join(genDir, "secrets"), data); err != nil {
		fail("writing Docker secrets: %s", err)
	}
	done()

	// Step 4: Runtime directories + Docker IPv6
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

	// Step 5: Fail2ban
	printStep("Configuring Fail2ban")
	configureFail2ban(cmd)
	done()

	// Step 6: Move generated docker-compose.yml into place. Must happen before
	// any `docker compose -f` invocation below.
	printStep("Writing docker-compose.yml")
	composeSrc := filepath.Join(genDir, "docker-compose.yml")
	composeDst := filepath.Join(filepath.Dir(configDir), "docker-compose.yml")
	if composeDst == "/docker-compose.yml" {
		composeDst = "/opt/vectis/docker-compose.production.yml"
	}
	composeContent, err := os.ReadFile(composeSrc)
	if err != nil {
		fail("reading generated compose file %s: %s", composeSrc, err)
	}
	if err := os.WriteFile(composeDst, composeContent, 0644); err != nil {
		fail("writing %s: %s", composeDst, err)
	}
	done()

	// Step 7: Pull container images. Doing this before `up` keeps timing
	// failures separate from health-wait failures.
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

	// Step 8: Bring up Postgres alone and block until it's healthy. Postgres
	// must be reachable before migrations can run, and the bootstrap script
	// (init-users.sh) creates the vectis_api role on the same first start.
	printStep("Starting Postgres and waiting for it to become healthy")
	pgUp := exec.Command("docker", "compose", "-f", composeDst, "up", "-d", "--wait", "postgres")
	pgUp.Stdout = os.Stdout
	pgUp.Stderr = os.Stderr
	if err := pgUp.Run(); err != nil {
		fail("postgres did not become healthy: %s", err)
	}
	done()

	// Step 9: Run database migrations. Connect via 127.0.0.1 because the
	// generated compose publishes Postgres on the loopback interface; the
	// `postgres` hostname only resolves inside the vectis-data Docker network.
	printStep("Running database migrations")
	logger := logging.NewLogger("warn")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	dbHost := secrets.Database.Host
	if dbHost == "postgres" {
		dbHost = "127.0.0.1"
	}
	dbCfg := database.ConfigFromSecrets(
		dbHost, secrets.Database.Port, secrets.Database.Name,
		secrets.Database.APIUser, secrets.Database.APIPassword,
	)

	// Belt-and-braces: even with a TCP-aware healthcheck, on slow VPSes
	// docker-proxy can take a beat to bind the published port after the
	// container reports healthy. Retry briefly before giving up.
	var pool *pgxpool.Pool
	for attempt := 1; attempt <= 15; attempt++ {
		pool, err = database.NewPool(ctx, dbCfg, logger)
		if err == nil {
			break
		}
		if attempt == 15 {
			fail("cannot connect to database at %s:%d after %d attempts: %s", dbHost, secrets.Database.Port, attempt, err)
		}
		time.Sleep(2 * time.Second)
	}
	defer pool.Close()

	if err := database.RunMigrations(dbCfg.DSN(), logger); err != nil {
		fail("migration failed: %s", err)
	}
	done()

	// Step 10: Seed the initial admin account
	printStep("Creating initial admin account")
	adminRepo := repository.NewAdminRepo(pool)

	existing, _ := adminRepo.GetByEmail(ctx, secrets.API.AdminEmail)
	adminPassword := secrets.API.AdminPassword

	if existing == nil {
		if adminPassword == "CHANGE_ME_admin_password" {
			adminPassword = generateRandomPassword(16)
		}

		hash, err := auth.HashPassword(adminPassword)
		if err != nil {
			fail("hashing admin password: %s", err)
		}

		_, err = adminRepo.Create(ctx, repository.AdminCreate{
			Email:        secrets.API.AdminEmail,
			PasswordHash: hash,
		})
		if err != nil {
			fail("creating admin: %s", err)
		}
	}
	done()

	// Step 11: Bring up the rest of the stack. Postgres is already healthy;
	// `up -d` against the same compose file is a no-op for it and starts
	// everything else.
	printStep("Starting remaining services")
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
