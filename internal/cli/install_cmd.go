package cli

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/engine"
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

	// Refuse to install with the placeholder hostname. Otherwise the
	// generated traefik router binds to `mail.example.com`, Let's Encrypt
	// attempts a cert for a domain the user doesn't own, and the admin UI
	// is permanently unreachable because there is no matching DNS record.
	if cfg.Hostname == "" || strings.HasSuffix(cfg.Hostname, ".example.com") || cfg.Hostname == "example.com" {
		fail("config.yaml 'hostname' is still the placeholder (%q).\n\n"+
			"  Edit %s/config.yaml and set 'hostname' to the FQDN that points at this\n"+
			"  server (e.g. mail.yourdomain.com). Also set 'tls.email' to the address\n"+
			"  Let's Encrypt should use for renewal reminders. Then re-run `vectis install`.",
			cfg.Hostname, configDir)
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
	// any `docker compose -f` invocation below. Always writes to the canonical
	// /opt/vectis location so `vectis status`, ops runbooks, and manual
	// operators all share a single compose path regardless of --config-dir.
	printStep("Writing docker-compose.yml")
	composeSrc := filepath.Join(genDir, "docker-compose.yml")
	composeDst := "/opt/vectis/docker-compose.production.yml"
	if err := os.MkdirAll(filepath.Dir(composeDst), 0755); err != nil {
		fail("creating %s: %s", filepath.Dir(composeDst), err)
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

	// Step 9: Run database migrations inside a one-shot api container on the
	// vectis-data network. The host cannot reach Postgres directly because
	// vectis-data is `internal: true` — Docker silently drops any port
	// publish from internal networks, so all DB-touching bootstrap work
	// runs in-container where `postgres` resolves over Docker DNS.
	printStep("Running database migrations")
	migrateArgs := composeRunAPI(composeDst, "vectis", "migrate", "up")
	runMigrate := exec.Command(migrateArgs[0], migrateArgs[1:]...)
	runMigrate.Stdout = os.Stdout
	runMigrate.Stderr = os.Stderr
	if err := runMigrate.Run(); err != nil {
		fail("migration failed: %s", err)
	}
	done()

	// Step 10: Seed the initial admin account via the same one-shot path.
	// `vectis admin init` is idempotent: no-op if the admin already exists,
	// otherwise creates it (and prints a generated password when the secrets
	// file still carries the placeholder).
	printStep("Creating initial admin account")
	adminArgs := composeRunAPI(composeDst, "vectis", "admin", "init")
	runAdmin := exec.Command(adminArgs[0], adminArgs[1:]...)
	var adminOut bytes.Buffer
	runAdmin.Stdout = &adminOut
	runAdmin.Stderr = os.Stderr
	if err := runAdmin.Run(); err != nil {
		fail("admin init failed: %s", err)
	}
	// Surface any generated password line to the caller.
	adminOutput := adminOut.String()
	fmt.Fprint(cmd.OutOrStdout(), adminOutput)
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

	// Print success banner. The host-level DNS records are shown here so a
	// first-time user can get the admin UI reachable without hunting through
	// docs. Per-mail-domain records (MX / SPF / DKIM / DMARC) are emitted by
	// `vectis domain add` because they don't exist yet on a fresh install.
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "═══════════════════════════════════════════")
	fmt.Fprintln(cmd.OutOrStdout(), "  Vectis is ready!")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "  Admin URL:   https://%s/admin\n", cfg.Hostname)
	fmt.Fprintf(cmd.OutOrStdout(), "  Admin email: %s\n", secrets.API.AdminEmail)
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "  (see 'Creating initial admin account' output above for")
	fmt.Fprintln(cmd.OutOrStdout(), "   the generated admin password, if one was created)")
	fmt.Fprintln(cmd.OutOrStdout())

	printHostnameDNS(cmd, cfg.Hostname)

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "  Next steps:")
	fmt.Fprintln(cmd.OutOrStdout(), "  1. Publish the records above at your DNS provider")
	fmt.Fprintln(cmd.OutOrStdout(), "  2. Wait for DNS to propagate, then open the Admin URL")
	fmt.Fprintln(cmd.OutOrStdout(), "  3. Add your first mail domain — 'vectis domain add'")
	fmt.Fprintln(cmd.OutOrStdout(), "     will print the MX / SPF / DKIM / DMARC records you need")
	fmt.Fprintln(cmd.OutOrStdout(), "     to publish for that sending domain.")
	fmt.Fprintln(cmd.OutOrStdout(), "═══════════════════════════════════════════")

	return nil
}

// printHostnameDNS emits the records a first-time installer needs at the
// registrar before the admin UI is reachable: the A record for the Vectis
// hostname and a reminder that PTR (reverse DNS) lives at the VPS provider,
// not the registrar. Public-IP lookup is best-effort — if it fails we print
// a placeholder so the user knows what shape to fill in.
func printHostnameDNS(cmd *cobra.Command, hostname string) {
	publicIP := detectPublicIP()
	ipField := publicIP
	if ipField == "" {
		ipField = "<this server's public IPv4>"
	}

	fmt.Fprintln(cmd.OutOrStdout(), "  DNS records you must publish now:")
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintf(cmd.OutOrStdout(), "    A     %s.   →  %s\n", hostname, ipField)
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "  Also at your VPS provider (not the registrar):")
	fmt.Fprintf(cmd.OutOrStdout(), "    PTR   %s   →  %s.\n", ipField, hostname)
	fmt.Fprintln(cmd.OutOrStdout(), "    (required for outbound mail to avoid being rejected as spam)")

	if publicIP == "" {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), "  Note: public IP auto-detection failed — substitute your VPS's")
		fmt.Fprintln(cmd.OutOrStdout(), "  public IPv4 for the placeholder above.")
	}
}

// detectPublicIP asks a handful of well-known IP-echo endpoints for this
// server's public IPv4. Returns "" if all of them fail or give nonsense.
// Kept best-effort and tightly time-bounded — the banner has to print in a
// few seconds even on a flaky egress path.
func detectPublicIP() string {
	endpoints := []string{
		"https://api.ipify.org",
		"https://ifconfig.me/ip",
		"https://icanhazip.com",
	}
	for _, url := range endpoints {
		out, err := exec.Command("curl", "-fsS", "--max-time", "3", "-4", url).Output()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(out))
		if net.ParseIP(ip) != nil && !strings.Contains(ip, ":") {
			return ip
		}
	}
	return ""
}

// composeRunAPI returns the `docker compose run` invocation that executes
// the given command inside a transient api container on the same networks
// as the running stack. The api image's entrypoint is `vectis`, so args[0]
// must be "vectis" or a sibling binary baked into the image.
func composeRunAPI(composePath string, args ...string) []string {
	return append([]string{
		"docker", "compose", "-f", composePath,
		"run", "--rm", "--no-deps",
		"--entrypoint", args[0],
		"api",
	}, args[1:]...)
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
