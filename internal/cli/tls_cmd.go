package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	vectistls "github.com/Veltara-Works/vectis/internal/tls"
	"github.com/spf13/cobra"
)

var tlsCmd = &cobra.Command{
	Use:   "tls",
	Short: "TLS certificate management commands",
}

var tlsGenerateSelfSignedCmd = &cobra.Command{
	Use:   "self-signed",
	Short: "Generate a self-signed TLS certificate for development",
	RunE:  runTLSGenerateSelfSigned,
}

var tlsGenerateInternalCmd = &cobra.Command{
	Use:   "generate-internal",
	Short: "Generate internal mTLS certificates for API ↔ orchestrator communication",
	RunE:  runTLSGenerateInternal,
}

var tlsStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show TLS certificate status for all services",
	RunE:  runTLSStatus,
}

var tlsCertDir string
var tlsHostname string
var tlsInternalCertDir string

var (
	tlsExtractACMEJSON     string
	tlsExtractOutDir       string
	tlsExtractHostname     string
	tlsExtractReloadPost   string
	tlsExtractReloadDove   string
	tlsExtractWatch        bool
	tlsExtractPollInterval time.Duration
)

var tlsExtractTraefikCmd = &cobra.Command{
	Use:   "extract-traefik",
	Short: "Extract a TLS cert from Traefik's acme.json into the mail cert dir",
	Long: `Read Traefik's acme.json, find the certificate whose main/SAN matches
--hostname, and write fullchain.pem + privkey.pem into --out-dir atomically.

With --watch the command runs indefinitely, polling acme.json every
--poll-interval (default 30s) and re-extracting on change. When the cert
content changes, --reload-postfix and/or --reload-dovecot container names
are signalled with SIGHUP via 'docker kill' so Postfix/Dovecot pick up
the renewed cert without a full restart.

This is the replacement for the old acme.sh sidecar — Traefik already
issues and renews the mail cert as a side-effect of serving the admin UI,
so we just mirror it into the mail-certs volume.`,
	RunE: runTLSExtractTraefik,
}

func runTLSExtractTraefik(cmd *cobra.Command, args []string) error {
	if tlsExtractHostname == "" {
		return fmt.Errorf("--hostname is required")
	}
	if tlsExtractACMEJSON == "" {
		return fmt.Errorf("--acme-json is required")
	}
	if tlsExtractOutDir == "" {
		return fmt.Errorf("--out-dir is required")
	}

	logger := slog.New(slog.NewJSONHandler(cmd.OutOrStdout(), &slog.HandlerOptions{Level: slog.LevelInfo}))

	opts := vectistls.ExtractOptions{
		ACMEJSONPath:  tlsExtractACMEJSON,
		Hostname:      tlsExtractHostname,
		OutDir:        tlsExtractOutDir,
		ReloadPostfix: tlsExtractReloadPost,
		ReloadDovecot: tlsExtractReloadDove,
		PollInterval:  tlsExtractPollInterval,
		Logger:        logger,
	}

	if !tlsExtractWatch {
		res, err := vectistls.Extract(opts)
		if err != nil {
			return err
		}
		if !res.Found {
			fmt.Fprintln(cmd.ErrOrStderr(), "certificate not found in acme.json (traefik has not issued yet)")
			os.Exit(1)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "extracted cert (resolver=%s, changed=%t)\n", res.Resolver, res.Changed)
		return nil
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()
	return vectistls.Watch(ctx, opts)
}

func runTLSGenerateSelfSigned(cmd *cobra.Command, args []string) error {
	if tlsHostname == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --hostname is required")
		os.Exit(1)
	}

	if err := vectistls.GenerateSelfSigned(tlsCertDir, tlsHostname); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Self-signed certificate generated:\n")
	fmt.Fprintf(cmd.OutOrStdout(), "  Certificate: %s/fullchain.pem\n", tlsCertDir)
	fmt.Fprintf(cmd.OutOrStdout(), "  Private key: %s/privkey.pem\n", tlsCertDir)
	fmt.Fprintf(cmd.OutOrStdout(), "  Hostname:    %s\n", tlsHostname)
	fmt.Fprintf(cmd.OutOrStdout(), "  Valid for:   365 days\n")
	fmt.Fprintln(cmd.OutOrStdout(), "\nWARNING: Self-signed certificates are for development only.")
	return nil
}

func runTLSGenerateInternal(cmd *cobra.Command, args []string) error {
	if vectistls.InternalCertsExist(tlsInternalCertDir) {
		fmt.Fprintln(cmd.ErrOrStderr(), "Warning: internal mTLS certificates already exist in "+tlsInternalCertDir)
		fmt.Fprintln(cmd.ErrOrStderr(), "Re-generating will invalidate existing certificates.")
		fmt.Fprintln(cmd.ErrOrStderr(), "Both API and orchestrator containers must be restarted after regeneration.")
		fmt.Fprintln(cmd.ErrOrStderr())
	}

	if err := vectistls.GenerateInternalCerts(tlsInternalCertDir); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Internal mTLS certificates generated in %s:\n", tlsInternalCertDir)
	fmt.Fprintf(cmd.OutOrStdout(), "  CA certificate: %s/ca.pem\n", tlsInternalCertDir)
	fmt.Fprintf(cmd.OutOrStdout(), "  Server cert:    %s/server.pem     (orchestrator)\n", tlsInternalCertDir)
	fmt.Fprintf(cmd.OutOrStdout(), "  Server key:     %s/server-key.pem (orchestrator)\n", tlsInternalCertDir)
	fmt.Fprintf(cmd.OutOrStdout(), "  Client cert:    %s/client.pem     (API server)\n", tlsInternalCertDir)
	fmt.Fprintf(cmd.OutOrStdout(), "  Client key:     %s/client-key.pem (API server)\n", tlsInternalCertDir)
	fmt.Fprintln(cmd.OutOrStdout())
	fmt.Fprintln(cmd.OutOrStdout(), "To enable mTLS, add to secrets.yaml:")
	fmt.Fprintf(cmd.OutOrStdout(), "  orchestrator:\n    mtls_cert_dir: %s\n", tlsInternalCertDir)
	fmt.Fprintln(cmd.OutOrStdout(), "\nThen restart the API and orchestrator containers.")
	return nil
}

func runTLSStatus(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	certPaths := map[string]string{
		"mail":       tlsCertDir + "/fullchain.pem",
		"internal-ca": vectistls.InternalCertDir + "/ca.pem",
		"orch-server": vectistls.InternalCertDir + "/server.pem",
		"api-client":  vectistls.InternalCertDir + "/client.pem",
	}

	type certStatus struct {
		Service string            `json:"service"`
		Info    *vectistls.CertInfo `json:"info,omitempty"`
		Error   string            `json:"error,omitempty"`
	}

	var statuses []certStatus
	for service, path := range certPaths {
		info, err := vectistls.ReadCertInfo(path)
		if err != nil {
			statuses = append(statuses, certStatus{Service: service, Error: err.Error()})
		} else {
			statuses = append(statuses, certStatus{Service: service, Info: info})
		}
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(statuses, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		for _, s := range statuses {
			if s.Error != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "%-10s ✗ %s\n", s.Service+":", s.Error)
			} else {
				icon := "✓"
				if s.Info.IsExpired {
					icon = "✗ EXPIRED"
				} else if s.Info.DaysLeft < 14 {
					icon = "! expiring soon"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-10s %s  CN=%s  expires=%s  days_left=%d\n",
					s.Service+":", icon, s.Info.Subject,
					s.Info.NotAfter.Format("2006-01-02"), s.Info.DaysLeft)
			}
		}
	}
	return nil
}

func init() {
	tlsGenerateSelfSignedCmd.Flags().StringVar(&tlsCertDir, "cert-dir", "/etc/ssl/mail", "Directory to write certificates")
	tlsGenerateSelfSignedCmd.Flags().StringVar(&tlsHostname, "hostname", "", "Hostname for the certificate")
	tlsGenerateInternalCmd.Flags().StringVar(&tlsInternalCertDir, "cert-dir", vectistls.InternalCertDir, "Directory to write internal mTLS certificates")
	tlsStatusCmd.Flags().StringVar(&tlsCertDir, "cert-dir", "/etc/ssl/mail", "Directory containing certificates")

	tlsExtractTraefikCmd.Flags().StringVar(&tlsExtractACMEJSON, "acme-json", "/var/traefik/acme/acme.json", "Path to Traefik's acme.json")
	tlsExtractTraefikCmd.Flags().StringVar(&tlsExtractOutDir, "out-dir", "/etc/ssl/mail", "Directory to write fullchain.pem + privkey.pem")
	tlsExtractTraefikCmd.Flags().StringVar(&tlsExtractHostname, "hostname", "", "Hostname (cert's main domain or SAN) to extract")
	tlsExtractTraefikCmd.Flags().StringVar(&tlsExtractReloadPost, "reload-postfix", "", "Postfix container name to SIGHUP on cert change (empty = skip)")
	tlsExtractTraefikCmd.Flags().StringVar(&tlsExtractReloadDove, "reload-dovecot", "", "Dovecot container name to SIGHUP on cert change (empty = skip)")
	tlsExtractTraefikCmd.Flags().BoolVar(&tlsExtractWatch, "watch", false, "Run indefinitely, polling acme.json on an interval")
	tlsExtractTraefikCmd.Flags().DurationVar(&tlsExtractPollInterval, "poll-interval", 30*time.Second, "Interval between acme.json polls in watch mode")

	tlsCmd.AddCommand(tlsGenerateSelfSignedCmd)
	tlsCmd.AddCommand(tlsGenerateInternalCmd)
	tlsCmd.AddCommand(tlsStatusCmd)
	tlsCmd.AddCommand(tlsExtractTraefikCmd)
	RootCmd.AddCommand(tlsCmd)
}
