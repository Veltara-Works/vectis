package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/license"
)

// License verify exit codes follow the Pharlux operator convention so scripts
// and monitors can branch on the outcome without parsing output:
//
//	0  the token verifies and currently entitles a paid tier (LIVE or IN_GRACE)
//	1  a token is present but does NOT entitle — rejected (bad signature, wrong
//	   issuer/audience, unknown tier, …) or accepted-but-past-grace (downgraded)
//	2  operator/configuration error — no token to verify, secrets unreadable, or
//	   the JWKS could not be resolved from any layer (a build/config fault)
const (
	exitLicenseOK       = 0
	exitLicenseInvalid  = 1
	exitLicenseOperator = 2
)

var licenseCmd = &cobra.Command{
	Use:   "license",
	Short: "License management commands",
}

var (
	licenseVerifyToken   string
	licenseVerifyOffline bool
)

var licenseVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify the offline license token and report tier, grace state, and entitlements",
	Long: `Verify a ValidonX-issued license token (Ed25519 JWT, aud="vectis-mail")
against the trusted JWKS.

The token verified is, in order of precedence: the --token flag, else the
[license].token from secrets.yaml. Signature + claim verification is offline (no
network), but resolving the JWKS may fetch it live over HTTPS first (then on-disk
cache, then the embedded key) — pass --offline to skip the live fetch and verify
against the cache/embedded key only. The layer that satisfied the lookup is
reported so an operator can tell when an install is running on the build-time
embedded key.

Exit codes: 0 = valid and entitled (LIVE or IN_GRACE); 1 = a token is present
but does not entitle (rejected, or expired past the grace window); 2 = operator
error (no token configured, secrets unreadable, or JWKS resolution failed).`,
	RunE: runLicenseVerify,
}

// licenseExitCode maps a verdict to the operator exit code. entitled is true
// only when the token is cryptographically accepted AND still within the grace
// window — a past-grace token verifies but is downgraded, so it does not
// entitle (exit 1). A rejected token is exit 1 as well; exit 2 (operator error)
// is decided upstream before a verdict exists.
func licenseExitCode(v license.Verdict) (entitled bool, code int) {
	if v.Accepted && v.GraceState != license.GracePastGrace {
		return true, exitLicenseOK
	}
	return false, exitLicenseInvalid
}

// licenseVerifyJSON is the --json output shape.
type licenseVerifyJSON struct {
	JWKSSource   string            `json:"jwks_source"`
	Accepted     bool              `json:"accepted"`
	Entitled     bool              `json:"entitled"`
	Reason       string            `json:"reason,omitempty"`
	Tier         string            `json:"tier,omitempty"`
	GraceState   string            `json:"grace_state,omitempty"`
	Entitlements map[string]string `json:"entitlements,omitempty"`
	ExitCode     int               `json:"exit_code"`
}

func runLicenseVerify(cmd *cobra.Command, args []string) error {
	out, errw := cmd.OutOrStdout(), cmd.ErrOrStderr()
	jsonOutput, _ := cmd.Flags().GetBool("json")

	// Load secrets directly (not via loadSecrets, which os.Exit(1)s on failure)
	// so an unreadable/invalid secrets.yaml maps to the documented operator
	// exit code 2, not 1.
	configDir, _ := cmd.Flags().GetString("config-dir")
	secrets, err := config.LoadSecrets(configDir + "/secrets.yaml")
	if err != nil {
		fmt.Fprintf(errw, "Error: %s\n", err)
		os.Exit(exitLicenseOperator)
	}

	// Resolve the token: explicit flag wins over the configured one.
	token := licenseVerifyToken
	if token == "" && secrets.License != nil {
		token = secrets.License.Token
	}
	if token == "" {
		fmt.Fprintln(errw, "Error: no license token to verify (set [license].token in secrets.yaml or pass --token)")
		os.Exit(exitLicenseOperator)
	}

	// Build the resolver from the configured JWKS layers. --offline drops the
	// live layer so the check never touches the network (cache → embedded only).
	jwksURL := ""
	if secrets.License != nil && !licenseVerifyOffline {
		jwksURL = secrets.License.JWKSURL
	}
	cachePath := secrets.License.CachePath() // nil-receiver safe; returns the default path

	provider := license.NewProvider(license.NewResolver(jwksURL, cachePath))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	src, err := provider.Refresh(ctx)
	if err != nil {
		// Every layer failed, including the embedded fallback — a build/config
		// fault, not an invalid token.
		fmt.Fprintf(errw, "Error: could not resolve license JWKS: %s\n", err)
		os.Exit(exitLicenseOperator)
	}

	verdict := license.Verify(token, provider.Current(), time.Now(), license.VMPolicy())
	entitled, exitCode := licenseExitCode(verdict)

	if jsonOutput {
		res := licenseVerifyJSON{
			JWKSSource: string(src),
			Accepted:   verdict.Accepted,
			Entitled:   entitled,
			ExitCode:   exitCode,
		}
		if verdict.Accepted {
			res.Tier = verdict.InternalTier
			res.GraceState = string(verdict.GraceState)
			res.Entitlements = verdict.Entitlements
		} else {
			res.Reason = verdict.Reason
		}
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(out, string(b))
		os.Exit(exitCode)
	}

	fmt.Fprintln(out, "License verification")
	fmt.Fprintf(out, "  JWKS source:  %s\n", src)
	if !verdict.Accepted {
		fmt.Fprintln(out, "  Result:       REJECT")
		fmt.Fprintf(out, "  Reason:       %s\n", verdict.Reason)
		os.Exit(exitCode)
	}

	fmt.Fprintln(out, "  Result:       ACCEPT")
	fmt.Fprintf(out, "  Tier:         %s\n", verdict.InternalTier)
	fmt.Fprintf(out, "  Grace:        %s\n", verdict.GraceState)
	switch verdict.GraceState {
	case license.GraceInGrace:
		fmt.Fprintln(out, "  Note:         token has expired but is within the grace window — renew soon.")
	case license.GracePastGrace:
		fmt.Fprintln(out, "  Note:         token expired past the grace window — downgraded; entitlements revoked.")
	}
	if len(verdict.Entitlements) > 0 {
		keys := make([]string, 0, len(verdict.Entitlements))
		for k := range verdict.Entitlements {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintln(out, "  Entitlements:")
		for _, k := range keys {
			fmt.Fprintf(out, "    %s = %s\n", k, verdict.Entitlements[k])
		}
	}
	os.Exit(exitCode)
	return nil
}

func init() {
	licenseVerifyCmd.Flags().StringVar(&licenseVerifyToken, "token", "", "License JWT to verify (defaults to [license].token from secrets.yaml)")
	licenseVerifyCmd.Flags().BoolVar(&licenseVerifyOffline, "offline", false, "Skip the live JWKS fetch (use on-disk cache then embedded key only)")

	licenseCmd.AddCommand(licenseVerifyCmd)
	RootCmd.AddCommand(licenseCmd)
}
