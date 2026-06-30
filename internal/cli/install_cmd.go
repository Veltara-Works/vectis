package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

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
	totalSteps := 12
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

	// Same guardrail for tls.email and admin_email — non-interactive
	// install.sh (cloud-init, airgapped) can't prompt the operator and
	// leaves the placeholders in place. If we install with those, the
	// Let's Encrypt ACME account is registered against a bogus address
	// and all future alert emails go to admin@example.com, which bounces.
	//
	// Placeholder checks catch shipped-default values (@example.com);
	// malformed checks catch whatever garbage a pre-rc26 install.sh
	// without FQDN validation might have produced (whitespace, no @,
	// non-FQDN domains). Two layers behind the install.sh-side fixes.
	if cfg.TLS.Provider == "letsencrypt" {
		if cfg.TLS.Email == "" || isPlaceholderEmail(cfg.TLS.Email) {
			fail("config.yaml 'tls.email' is still the placeholder (%q).\n\n"+
				"  Edit %s/config.yaml and set 'tls.email' to a real address you control —\n"+
				"  Let's Encrypt will send cert-renewal reminders there. Then re-run `vectis install`.",
				cfg.TLS.Email, configDir)
		}
		if isMalformedEmail(cfg.TLS.Email) {
			fail("config.yaml 'tls.email' (%q) is not a valid email address.\n\n"+
				"  An email must have no whitespace, contain `@`, and use an FQDN for the\n"+
				"  domain (e.g. `admin@yourdomain.com`). Edit %s/config.yaml and re-run.",
				cfg.TLS.Email, configDir)
		}
	}
	if isPlaceholderEmail(secrets.API.AdminEmail) {
		fail("secrets.yaml 'api.admin_email' is still the placeholder (%q).\n\n"+
			"  Edit %s/secrets.yaml and set 'api.admin_email' to the address you'll use\n"+
			"  to log in to the admin UI. Then re-run `vectis install`.",
			secrets.API.AdminEmail, configDir)
	}
	if isMalformedEmail(secrets.API.AdminEmail) {
		fail("secrets.yaml 'api.admin_email' (%q) is not a valid email address.\n\n"+
			"  An email must have no whitespace, contain `@`, and use an FQDN for the\n"+
			"  domain (e.g. `admin@yourdomain.com`). Edit %s/secrets.yaml and re-run.",
			secrets.API.AdminEmail, configDir)
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
		"/var/vectis/license", // offline license JWKS cache (bind-mounted into vectis-api)
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
	// /etc/vectis location so the orchestrator, backup flow, `vectis update`,
	// ops runbooks, and manual operators all share a single compose path.
	// (Pre-rc25 installs wrote to /opt/vectis/docker-compose.production.yml,
	// which the orchestrator never looked at — see deferred-items.md §9.)
	printStep("Writing docker-compose.yml")
	composeSrc := filepath.Join(genDir, "docker-compose.yml")
	composeDst := "/etc/vectis/docker-compose.yml"
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
	// runs in-container where `postgres` resolves over Docker DNS. We use
	// `docker run` (NOT `docker compose run`) so a re-run against a live
	// stack can never detach the running api container — see dockerRunAPI.
	printStep("Running database migrations")
	apiImage, err := apiImageFromComposeFile(composeDst)
	if err != nil {
		fail("could not determine api image from %s: %s", composeDst, err)
	}
	migrateArgs := dockerRunAPI(apiImage, "vectis", "migrate", "up")
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
	// file still carries the placeholder). We capture the output, parse the
	// password out, and surface it in the final banner so operators using
	// scrollback-less web terminals don't lose it.
	printStep("Creating initial admin account")
	adminArgs := dockerRunAPI(apiImage, "vectis", "admin", "init")
	runAdmin := exec.Command(adminArgs[0], adminArgs[1:]...)
	var adminOut bytes.Buffer
	runAdmin.Stdout = &adminOut
	runAdmin.Stderr = os.Stderr
	if err := runAdmin.Run(); err != nil {
		fail("admin init failed: %s", err)
	}
	generatedAdminPassword := parseAdminPassword(adminOut.String())
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

	// Step 12: Traefik tries to issue its Let's Encrypt cert ~3 seconds
	// into compose-up. If the operator hasn't published their A record
	// yet — or DNS hasn't propagated — that first ACME attempt fails and
	// traefik won't retry until the next router request hits, which can
	// leave the admin URL serving a self-signed cert + tripping HSTS for
	// hours. Poll DNS for up to 60s; if it's already live, restart
	// traefik to trigger a fresh cert immediately.
	printStep("Waiting for DNS to come up so TLS can issue")
	publicIP := detectPublicIP()
	dnsLive := waitForHostnameDNS(cfg.Hostname, publicIP, 60*time.Second)

	// leCertOK drives the footer message below. Stays false if DNS wasn't
	// live (we never even try), or if the verification poll times out
	// without seeing a trusted cert on :443.
	leCertOK := false
	var leCertIssuer, leCertError string

	if dnsLive {
		_ = exec.Command("docker", "restart", "vectis-traefik").Run()
		fmt.Fprintln(cmd.OutOrStdout(), " DNS resolved — triggered cert issuance")

		// Verify the issuance actually landed. Before rc31 we just printed
		// "triggered cert issuance" and called the install done, which was
		// misleading when LE failed (rate-limited, :80 unreachable, wrong
		// tls.email, etc.) — the admin URL would serve Traefik's default
		// self-signed cert and users would blame DNS. Now we poll the local
		// :443 listener for up to 90s looking for a non-default cert; if
		// that times out, scrape traefik's logs for the actual ACME error
		// so operators see a real reason rather than a generic DNS hint.
		fmt.Fprint(cmd.OutOrStdout(), "  verifying Let's Encrypt issuance (up to 90s)...")
		leCertIssuer = waitForTrustedCert(cfg.Hostname, 90*time.Second)
		if leCertIssuer != "" {
			leCertOK = true
			fmt.Fprintf(cmd.OutOrStdout(), " issued by %s\n", leCertIssuer)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), " not yet")
			leCertError = scrapeTraefikACMEError()
		}
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), " DNS not live yet (see banner for retry command)")
	}

	// Print success banner. The host-level DNS records are shown here so a
	// first-time user can get the admin UI reachable without hunting through
	// docs. Per-mail-domain records (MX / SPF / DKIM / DMARC) are emitted by
	// `vectis domain add` because they don't exist yet on a fresh install.
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "═══════════════════════════════════════════")
	fmt.Fprintln(cmd.OutOrStdout(), "  Vectis is ready!")
	fmt.Fprintln(cmd.OutOrStdout())
	// Admin URL / email / password printed green-bold so they stand out
	// in a dense terminal scrollback. The password line especially — it
	// is unrecoverable, and a user skimming the banner who misses it
	// ends up locked out. Gated on isStdoutTTY() so `vectis install >
	// install.log` doesn't end up full of ANSI escape codes.
	fmt.Fprintf(cmd.OutOrStdout(), "  Admin URL:      %s\n", green(fmt.Sprintf("https://%s/admin", cfg.Hostname)))
	fmt.Fprintf(cmd.OutOrStdout(), "  Admin email:    %s\n", green(secrets.API.AdminEmail))
	if generatedAdminPassword != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "  Admin password: %s\n", green(generatedAdminPassword))
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), red("  !! SAVE THE PASSWORD ABOVE !!"))
		fmt.Fprintln(cmd.OutOrStdout(), "     It is shown only here — not written to disk, and not recoverable.")
		fmt.Fprintln(cmd.OutOrStdout(), "     Change it immediately after your first login.")
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "  Admin password: (admin already existed — this install left it unchanged)")
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), "  If you have lost it, generate a new one with:")
		fmt.Fprintln(cmd.OutOrStdout(), "    docker run --rm \\")
		fmt.Fprintln(cmd.OutOrStdout(), "      --network vectis_vectis-data \\")
		fmt.Fprintln(cmd.OutOrStdout(), "      -v /etc/vectis:/etc/vectis:ro \\")
		fmt.Fprintln(cmd.OutOrStdout(), "      --entrypoint vectis \\")
		fmt.Fprintln(cmd.OutOrStdout(), "      ghcr.io/veltara-works/vectis-api:latest \\")
		fmt.Fprintln(cmd.OutOrStdout(), "      admin reset-password <email>")
	}
	fmt.Fprintln(cmd.OutOrStdout())

	printHostnameDNS(cmd, cfg.Hostname)

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "  Next steps:")
	fmt.Fprintln(cmd.OutOrStdout(), "  1. Publish the records above at your DNS provider")
	fmt.Fprintln(cmd.OutOrStdout(), "  2. Wait for DNS to propagate, then open the Admin URL")
	fmt.Fprintln(cmd.OutOrStdout(), "  3. Add your first mail domain — 'vectis domain add'")
	fmt.Fprintln(cmd.OutOrStdout(), "     will print the MX / SPF / DKIM / DMARC records you need")
	fmt.Fprintln(cmd.OutOrStdout(), "     to publish for that sending domain.")
	fmt.Fprintln(cmd.OutOrStdout())
	// TLS footer varies based on what actually happened with cert issuance.
	// Happy path (leCertOK): one-line confirmation, issuer name named.
	// Failed path (leCertError != ""): surface the actual ACME error so
	// the operator can act on it instead of guessing at DNS propagation.
	// Unknown path (!dnsLive or verification timed out without a log hit):
	// fall back to the old generic hint.
	switch {
	case leCertOK:
		fmt.Fprintf(cmd.OutOrStdout(), "  TLS cert: issued by %s — admin URL is trusted and ready.\n", leCertIssuer)
	case leCertError != "":
		fmt.Fprintln(cmd.OutOrStdout(), red("  TLS cert: Let's Encrypt did NOT issue a cert. Traefik says:"))
		fmt.Fprintf(cmd.OutOrStdout(), "    %s\n", leCertError)
		fmt.Fprintln(cmd.OutOrStdout(), "  Full log: docker logs vectis-traefik")
		fmt.Fprintln(cmd.OutOrStdout(), "  Common causes: LE rate-limited, port 80 unreachable from")
		fmt.Fprintln(cmd.OutOrStdout(), "  the internet, or tls.email in config.yaml invalid.")
		fmt.Fprintln(cmd.OutOrStdout(), "  Fix the underlying issue, then: docker restart vectis-traefik")
	default:
		fmt.Fprintln(cmd.OutOrStdout(), "  TLS cert: Let's Encrypt issuance happens automatically as soon")
		fmt.Fprintln(cmd.OutOrStdout(), "  as DNS is live. If the admin URL shows a cert warning, your DNS")
		fmt.Fprintln(cmd.OutOrStdout(), "  hadn't propagated when traefik first tried — force a retry with:")
		fmt.Fprintln(cmd.OutOrStdout(), "    docker restart vectis-traefik")
	}
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
	fmt.Fprintln(cmd.OutOrStdout(), "  At your domain registrar (GoDaddy, Namecheap, etc.)")
	fmt.Fprintln(cmd.OutOrStdout(), "  — or Cloudflare if your nameservers point there:")
	fmt.Fprintf(cmd.OutOrStdout(), "    A     %s.   →  %s\n", hostname, ipField)

	// IPv6 is only suggested when (a) we can reach the v6 internet AND
	// (b) reverse DNS for that v6 address already resolves back to this
	// hostname. Publishing AAAA without matching IPv6 PTR causes Gmail
	// and Outlook to reject mail outright — strictly worse than no AAAA.
	publicIPv6 := detectPublicIPv6()
	if publicIPv6 != "" {
		fmt.Fprintln(cmd.OutOrStdout())
		if reverseDNSMatches(publicIPv6, hostname) {
			fmt.Fprintln(cmd.OutOrStdout(), "  IPv6 detected with matching PTR — also publish AAAA:")
			fmt.Fprintf(cmd.OutOrStdout(), "    AAAA  %s.   →  %s\n", hostname, publicIPv6)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "  IPv6 detected but reverse DNS doesn't match this hostname.")
			fmt.Fprintln(cmd.OutOrStdout(), "  DO NOT publish an AAAA record yet — Gmail/Outlook will")
			fmt.Fprintln(cmd.OutOrStdout(), "  reject mail when v6 PTR doesn't match the EHLO hostname.")
			fmt.Fprintf(cmd.OutOrStdout(), "    Detected v6: %s\n", publicIPv6)
			fmt.Fprintf(cmd.OutOrStdout(), "    Set v6 PTR to %s at your VPS provider, then add:\n", hostname)
			fmt.Fprintf(cmd.OutOrStdout(), "      AAAA  %s.   →  %s\n", hostname, publicIPv6)
		}
	}

	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "  At your VPS provider's control panel (NOT the registrar):")
	fmt.Fprintf(cmd.OutOrStdout(), "    PTR   %s   →  %s.\n", ipField, hostname)
	fmt.Fprintln(cmd.OutOrStdout(), "    (reverse DNS — required or outbound mail is rejected as spam)")

	if publicIP == "" {
		fmt.Fprintln(cmd.OutOrStdout())
		fmt.Fprintln(cmd.OutOrStdout(), "  Note: public IP auto-detection failed — substitute your VPS's")
		fmt.Fprintln(cmd.OutOrStdout(), "  public IPv4 for the placeholder above.")
	}
}

// waitForHostnameDNS polls public DNS until the given hostname resolves
// to expectedIP, or until timeout. Used after `docker compose up` so the
// installer can trigger a fresh ACME issuance the moment DNS comes up,
// rather than letting the operator hit a self-signed cert (which then
// gets HSTS-pinned in their browser for hours).
//
// Resolution goes through the public resolver (1.1.1.1) so /etc/hosts
// fictions can't pretend DNS is live. expectedIP empty → just check
// that ANY A record exists.
func waitForHostnameDNS(hostname, expectedIP string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("dig", "+short", "+time=2", "+tries=1",
			"A", hostname, "@1.1.1.1").Output()
		if err == nil {
			for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
				ip := strings.TrimSpace(line)
				if net.ParseIP(ip) == nil {
					continue
				}
				if expectedIP == "" || ip == expectedIP {
					return true
				}
			}
		}
		time.Sleep(3 * time.Second)
	}
	return false
}

// isPlaceholderEmail returns true for addresses that are clearly
// default-values shipped with the config/secrets examples. Matches any
// address in the reserved example.com domain (RFC 2606) — both
// admin@example.com (shipped default) and my@example.com (historical).
func isPlaceholderEmail(email string) bool {
	e := strings.ToLower(strings.TrimSpace(email))
	if e == "" {
		return false // empty is handled separately so the error message is clearer
	}
	return strings.HasSuffix(e, "@example.com")
}

// isMalformedEmail returns true for addresses that cannot possibly work
// regardless of policy — whitespace, missing `@`, empty local or domain,
// or a domain part with no dot. Second layer of defence behind
// install.sh's hostname validation: even if install.sh somehow produced
// garbage (e.g. `admin@vectis preflight` from a fat-fingered hostname
// prompt in a pre-rc26 installer), this guardrail catches it before the
// ACME account registration or any config write happens. Returns false
// on empty input so the "missing value" case can produce a clearer
// error message upstream.
func isMalformedEmail(email string) bool {
	e := strings.TrimSpace(email)
	if e == "" {
		return false
	}
	if strings.ContainsAny(e, " \t\r\n") {
		return true
	}
	at := strings.LastIndex(e, "@")
	if at <= 0 || at == len(e)-1 {
		return true // missing @, empty local, or empty domain
	}
	domain := e[at+1:]
	if !strings.Contains(domain, ".") {
		return true // no dot in domain — not a FQDN
	}
	return false
}

// isStdoutTTY reports whether this process's stdout is connected to a
// terminal. Used to gate ANSI colour codes in the success banner —
// emitting them to a pipe or log file would pollute the output with
// unreadable escape sequences.
func isStdoutTTY() bool {
	stat, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// ANSI colour helpers — return `code` when stdout is a TTY, otherwise
// the empty string. Keeps the colour call-sites readable.
const (
	ansiReset    = "\033[0m"
	ansiGreenBld = "\033[1;32m"
	ansiRedBld   = "\033[1;31m"
)

func green(s string) string {
	if !isStdoutTTY() {
		return s
	}
	return ansiGreenBld + s + ansiReset
}

func red(s string) string {
	if !isStdoutTTY() {
		return s
	}
	return ansiRedBld + s + ansiReset
}

// parseAdminPassword pulls the `admin_password=...` line out of the
// key=value output emitted by `vectis admin init`. Returns "" if the
// line is absent (which means the admin already existed and no password
// was generated). Input is trusted — it comes from our own binary in a
// one-shot container — so no escaping gymnastics are needed.
func parseAdminPassword(output string) string {
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "admin_password=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "admin_password="))
		}
	}
	return ""
}

// detectPublicIP asks a handful of well-known IP-echo endpoints for this
// server's public IPv4. Returns "" if all of them fail or give nonsense.
// Kept best-effort and tightly time-bounded — the banner has to print in a
// few seconds even on a flaky egress path.
func detectPublicIP() string {
	return detectPublicIPFamily("-4")
}

// detectPublicIPv6 mirrors detectPublicIP for IPv6. Many VPSes have IPv6
// addresses but no AAAA published — that's fine, mail still works over
// v4. Returns "" if no public v6 is reachable, in which case AAAA-related
// banner output is skipped entirely.
func detectPublicIPv6() string {
	return detectPublicIPFamily("-6")
}

func detectPublicIPFamily(curlFlag string) string {
	// Family-specific hostnames so curl -4 / -6 succeeds at DNS too.
	endpoints := map[string][]string{
		"-4": {"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"},
		"-6": {"https://api6.ipify.org", "https://ifconfig.co", "https://ipv6.icanhazip.com"},
	}
	for _, url := range endpoints[curlFlag] {
		out, err := exec.Command("curl", "-fsS", "--max-time", "3", curlFlag, url).Output()
		if err != nil {
			continue
		}
		ip := strings.TrimSpace(string(out))
		parsed := net.ParseIP(ip)
		if parsed == nil {
			continue
		}
		isV6 := strings.Contains(ip, ":")
		if curlFlag == "-4" && !isV6 {
			return ip
		}
		if curlFlag == "-6" && isV6 {
			return ip
		}
	}
	return ""
}

// reverseDNSMatches returns true if the IP's PTR record exists and resolves
// to the given hostname (case-insensitive, trailing-dot tolerant). Used as
// a guardrail before recommending the operator publish AAAA — IPv6 mail
// without matching reverse DNS is silently rejected by Gmail/Outlook.
func reverseDNSMatches(ip, hostname string) bool {
	out, err := exec.Command("getent", "hosts", ip).Output()
	if err != nil {
		return false
	}
	fields := strings.Fields(strings.TrimSpace(string(out)))
	if len(fields) < 2 {
		return false
	}
	got := strings.TrimSuffix(strings.ToLower(fields[1]), ".")
	want := strings.TrimSuffix(strings.ToLower(hostname), ".")
	return got == want
}

// apiOneShotNetwork is the Docker network a one-shot api container must join
// to reach Postgres during bootstrap. It is `<compose project>_<network>` =
// `vectis_vectis-data` (the install always uses the `vectis` project name).
// Mirrors the manual-recovery command printed below and in admin_cmd.go.
const apiOneShotNetwork = "vectis_vectis-data"

// apiImageFromComposeFile reads the rendered compose file and returns the
// fully-qualified vectis-api image ref, including the version tag that was
// rendered into it. The compose file on disk is the single source of truth
// for the version being installed, so we never have to thread the version
// through here separately.
func apiImageFromComposeFile(composePath string) (string, error) {
	data, err := os.ReadFile(composePath)
	if err != nil {
		return "", err
	}
	img := pickAPIImage(string(data))
	if img == "" {
		return "", fmt.Errorf("no vectis-api image line found in %s", composePath)
	}
	return img, nil
}

// pickAPIImage scans rendered compose YAML for the api service's image ref.
// It is pure (no I/O) so it can be unit-tested. It matches the `image:` line
// whose value contains "/vectis-api:" — unique to the api service (the
// orchestrator is "/vectis-orchestrator:", postfix "/vectis-postfix:", etc).
func pickAPIImage(composeYAML string) string {
	for _, line := range strings.Split(composeYAML, "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "image:") {
			continue
		}
		ref := strings.TrimSpace(strings.TrimPrefix(t, "image:"))
		if strings.Contains(ref, "/vectis-api:") {
			return ref
		}
	}
	return ""
}

// dockerRunAPI returns the `docker run` invocation that executes the given
// command inside a one-shot api container attached to the vectis-data network,
// with the host config dir mounted read-only. The api image's entrypoint is
// `vectis`, so args[0] must be "vectis" (or a sibling binary baked into the
// image) and args[1:] are its arguments.
//
// Why `docker run` and NOT `docker compose run`: compose's transient run
// container takes the api service's network aliases, which forces compose to
// temporarily DETACH the live vectis-api container from its `internal: true`
// networks. If the transient container then fails to re-attach (alias races,
// among others), compose exits WITHOUT restoring the live container, leaving
// vectis-api stranded off vectis_vectis-data and unable to reach Postgres
// until `docker network connect` is run by hand (confirmed live on prod
// 2026-04-27). `docker run` joins the named network directly and never touches
// the live container, so it is safe to run against a live stack and safe to
// repeat. See internal/cli/admin_cmd.go for the operator-facing equivalent.
func dockerRunAPI(image string, args ...string) []string {
	return append([]string{
		"docker", "run", "--rm",
		"--network", apiOneShotNetwork,
		"-v", "/etc/vectis:/etc/vectis:ro",
		"--entrypoint", args[0],
		image,
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

// generateRandomPassword returns a hex-encoded random password carrying nbytes
// bytes (nbytes*8 bits) of entropy — a 2*nbytes-character string. It surfaces
// the crypto/rand error instead of silently emitting an all-zero or low-entropy
// password if the system RNG is unavailable, and no longer truncates the hex
// (which previously discarded half the generated entropy — audit #148/176).
func generateRandomPassword(nbytes int) (string, error) {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("read random bytes: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// waitForTrustedCert polls the local Traefik listener on :443 for up to
// timeout looking for a cert whose issuer is NOT Traefik's built-in
// default. Returns the issuer CN (e.g. "R12" for Let's Encrypt) on
// success, or "" on timeout.
//
// Uses crypto/tls.Dial with InsecureSkipVerify because we're only
// inspecting the cert metadata, not trusting it for communication. SNI
// is set to hostname so Traefik serves the right cert instead of the
// default.
//
// When Traefik hasn't yet obtained a cert (rate-limited, challenge
// failed, still retrying), it serves a self-signed "TRAEFIK DEFAULT
// CERT" — issuer.CommonName == "TRAEFIK DEFAULT CERT". We treat any
// non-default issuer as success, including custom intermediates, so
// operators using a non-Let's-Encrypt ACME CA don't false-fail here.
func waitForTrustedCert(hostname string, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		rawConn, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:443")
		cancel()
		if err != nil {
			time.Sleep(3 * time.Second)
			continue
		}
		conn := tls.Client(rawConn, &tls.Config{
			ServerName:         hostname,
			InsecureSkipVerify: true, //nolint:gosec // inspecting only
		})
		if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			_ = conn.Close()
			time.Sleep(3 * time.Second)
			continue
		}
		if err := conn.Handshake(); err != nil {
			_ = conn.Close()
			time.Sleep(3 * time.Second)
			continue
		}
		certs := conn.ConnectionState().PeerCertificates
		_ = conn.Close()
		if len(certs) == 0 {
			time.Sleep(3 * time.Second)
			continue
		}
		issuer := certs[0].Issuer.CommonName
		if issuer != "" && !strings.Contains(strings.ToUpper(issuer), "TRAEFIK") {
			return issuer
		}
		time.Sleep(3 * time.Second)
	}
	return ""
}

// scrapeTraefikACMEError runs `docker logs --since=2m vectis-traefik`
// and passes the combined output to extractACMEErrorFromLogs. Split in
// two so the parser is unit-testable without shelling out to docker.
func scrapeTraefikACMEError() string {
	cmd := exec.Command("docker", "logs", "--since=2m", "vectis-traefik")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return extractACMEErrorFromLogs(string(out))
}

// extractACMEErrorFromLogs scans Traefik docker-logs output for the
// most recent ACME-related error line and returns a condensed excerpt.
// Returns "" if nothing matched.
//
// Traefik emits JSON log lines. The useful fields for us are `level`
// ("error"), the `error` field (the actual upstream cause), and
// `message` (Traefik's wrapper text). We prefer `error` when present
// (concrete reason like "acme: error: 429 :: rateLimited") and fall
// back to `message` when it's absent. Plain-text log lines (rare on
// traefik 3.x but possible) go through a keyword-match path.
func extractACMEErrorFromLogs(logs string) string {
	var last string
	for _, raw := range strings.Split(logs, "\n") {
		if raw == "" {
			continue
		}
		var rec map[string]any
		if jerr := json.Unmarshal([]byte(raw), &rec); jerr != nil {
			lower := strings.ToLower(raw)
			if strings.Contains(lower, "acme") &&
				(strings.Contains(lower, "error") || strings.Contains(lower, "unable") || strings.Contains(lower, "ratelimit")) {
				last = condenseLine(raw)
			}
			continue
		}
		level, _ := rec["level"].(string)
		if level != "error" {
			continue
		}
		msg, _ := rec["message"].(string)
		errField, _ := rec["error"].(string)
		combined := strings.TrimSpace(msg + " " + errField)
		lower := strings.ToLower(combined)
		if !strings.Contains(lower, "acme") && !strings.Contains(lower, "ratelimit") &&
			!strings.Contains(lower, "unable to obtain") {
			continue
		}
		chosen := errField
		if chosen == "" {
			chosen = msg
		}
		last = condenseLine(chosen)
	}
	return last
}

// condenseLine trims whitespace and collapses multi-line error bodies
// into a single line so the banner stays readable. Also caps length at
// 200 chars with an ellipsis so a novel-length upstream error message
// doesn't swallow the terminal.
func condenseLine(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	for strings.Contains(s, "  ") {
		s = strings.ReplaceAll(s, "  ", " ")
	}
	s = strings.TrimSpace(s)
	if len(s) > 200 {
		s = s[:197] + "..."
	}
	return s
}

func init() {
	installCmd.Flags().StringP("output", "o", "/var/vectis/generated", "Output directory for generated configs")
	RootCmd.AddCommand(installCmd)
}
