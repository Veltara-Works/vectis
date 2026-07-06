package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/orchestrator"
	"github.com/Veltara-Works/vectis/internal/releasesign"
	vectistls "github.com/Veltara-Works/vectis/internal/tls"
	"github.com/Veltara-Works/vectis/internal/version"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update management commands",
}

var updatePlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Generate an update plan",
	Long:  "Check for available updates and generate a plan showing container version changes, config changes, and migrations.",
	RunE:  runUpdatePlan,
}

var updateApplyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply a pending update plan",
	Long:  "Execute the most recently generated update plan. Use --force to plan and apply in one step.",
	RunE:  runUpdateApply,
}

var updateRollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Roll back the last update",
	Long:  "Roll back to the state before the last successful update. Restores the database snapshot and reverts container images.",
	RunE:  runUpdateRollback,
}

var updateSelfCmd = &cobra.Command{
	Use:   "self",
	Short: "Refresh CLI binary and force-recreate the orchestrator and API containers at their currently pinned tags",
	Long: `Self-update is a recovery tool, not an upgrade path.

It does two things:
  1. Refreshes /usr/local/bin/vectis from the latest published stable release on
     dl.vectismail.com (best-effort; warns and continues on failure).
  2. Force-recreates the vectis-orchestrator and vectis-api containers using
     whatever image tag is currently pinned in /etc/vectis/docker-compose.yml.
     It does NOT change those tags. To bump orchestrator/api to a new version,
     use 'vectis update apply' (the orchestrator-driven path that rewrites
     compose tags atomically before recreating).

Use 'vectis update self' when:
  - The host CLI binary is stale (older releases of secrets.yaml's schema may
    refuse to parse on an old binary, which blocks 'vectis update plan/apply').
  - The orchestrator-driven Apply has wedged and you need to force-cycle the
    orchestrator and API at their current versions to recover.

Use 'vectis update apply' for actual version bumps.`,
	RunE: runUpdateSelf,
}

var (
	updateForce bool
)

// newOrchestratorClient creates an orchestrator.Client from secrets.yaml.
func newOrchestratorClient(cmd *cobra.Command) (*orchestrator.Client, error) {
	secrets, err := loadSecrets(cmd)
	if err != nil {
		return nil, fmt.Errorf("loading secrets: %w", err)
	}

	// When running on the host, talk to localhost; inside Docker, use the service name.
	baseURL := "http://localhost:8081"
	if os.Getenv("VECTIS_ORCHESTRATOR_URL") != "" {
		baseURL = os.Getenv("VECTIS_ORCHESTRATOR_URL")
	}

	// Prefer mTLS if cert directory is configured.
	if secrets.Orchestrator.MTLSCertDir != "" {
		if baseURL == "http://localhost:8081" {
			baseURL = "https://localhost:8081"
		}
		tlsCfg, err := vectistls.NewClientTLSConfig(secrets.Orchestrator.MTLSCertDir)
		if err != nil {
			return nil, fmt.Errorf("load mTLS certs: %w", err)
		}
		return orchestrator.NewMTLSClient(baseURL, tlsCfg), nil
	}

	// Fallback: bearer token.
	token := secrets.Orchestrator.Token
	if token == "" {
		return nil, fmt.Errorf("orchestrator token not found in secrets.yaml")
	}
	return orchestrator.NewClient(baseURL, token), nil
}

// --- vectis update plan ---

func runUpdatePlan(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	client, err := newOrchestratorClient(cmd)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	plan, err := client.Plan(ctx)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(plan, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}

	if plan.IsEmpty() {
		fmt.Fprintln(cmd.OutOrStdout(), "No updates available.")
		for _, w := range plan.Warnings {
			fmt.Fprintf(cmd.OutOrStdout(), "  ! %s\n", w)
		}
		return nil
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Update plan generated:")
	if plan.ReleaseTag != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "  Release channel target: %s\n", plan.ReleaseTag)
	}
	for _, w := range plan.Warnings {
		fmt.Fprintf(cmd.OutOrStdout(), "  ! %s\n", w)
	}
	fmt.Fprintln(cmd.OutOrStdout())

	if len(plan.Changes) > 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "  Container changes:")
		for _, c := range plan.Changes {
			switch {
			case c.OldImage != "" && c.NewImage != "":
				fmt.Fprintf(cmd.OutOrStdout(), "    %-12s %s  %s -> %s\n", c.Service+":", c.Type, c.OldImage, c.NewImage)
			case c.NewImage != "":
				fmt.Fprintf(cmd.OutOrStdout(), "    %-12s %s  %s\n", c.Service+":", c.Type, c.NewImage)
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "    %-12s %s  %s\n", c.Service+":", c.Type, c.Detail)
			}
		}
		fmt.Fprintln(cmd.OutOrStdout())
	}

	if plan.MigrationsUp > 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "  Database migrations: %d pending\n", plan.MigrationsUp)
		fmt.Fprintln(cmd.OutOrStdout())
	}

	fmt.Fprintln(cmd.OutOrStdout(), "  Run 'vectis update apply' to execute this plan.")
	fmt.Fprintln(cmd.OutOrStdout(), "  Plan expires if system state changes before apply.")
	return nil
}

// --- vectis update apply ---

func runUpdateApply(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	client, err := newOrchestratorClient(cmd)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	// If --force, we plan+apply in one step.
	result, err := client.Apply(ctx, updateForce)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	// Poll for completion if the apply is still running.
	if result.Status == "running" {
		result, err = pollApplyStatus(ctx, client, cmd, jsonOutput)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
			os.Exit(1)
		}
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	}

	switch result.Status {
	case "success":
		// Keep the host CLI in lockstep with the freshly-deployed containers.
		// `update apply` swaps the container images but NOT this host binary, so
		// without this a cutover leaves /usr/local/bin/vectis stale until the
		// operator remembers to run `vectis update self` — the gap that left a
		// v0.5.0-dev stray driving prod cutovers. Best-effort, reusing the same
		// refreshCLIBinary mechanism as `update self` step 1: it sha256-verifies,
		// only touches /usr/local/bin/vectis (skips custom installs), no-ops when
		// already current, and the atomic rename only affects the NEXT invocation
		// — so it can never disrupt the apply that just succeeded.
		//
		// Run in BOTH human and --json modes: automation that drives apply with
		// --json is exactly where a silently-stale host CLI bites. The ApplyResult
		// JSON was already emitted above, so in --json mode we refresh silently;
		// only human mode prints a status line.
		cliMsg, cliErr := refreshCLIBinary()
		if !jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), "\nUpdate applied successfully.")
			fmt.Fprint(cmd.OutOrStdout(), "Refreshing host CLI binary... ")
			if cliErr != nil {
				fmt.Fprintf(cmd.OutOrStdout(), "skipped (%s)\n", cliErr.Error())
			} else {
				fmt.Fprintln(cmd.OutOrStdout(), cliMsg)
			}
		}
		// A signature-verification failure on the host-CLI refresh is an active-
		// attack signal, not a benign skip — surface it loudly on stderr in BOTH
		// modes (stdout carries the ApplyResult JSON) and exit non-zero so
		// automation can't mistake tampering for a network blip (audit U-5). The
		// apply itself already succeeded; exit code 3 distinguishes this case.
		if errors.Is(cliErr, errReleaseVerification) {
			fmt.Fprintf(cmd.ErrOrStderr(), "\nSECURITY: host CLI refresh signature verification FAILED: %v\n", cliErr)
			fmt.Fprintln(cmd.ErrOrStderr(), "Containers were updated, but /usr/local/bin/vectis was NOT refreshed because the downloaded binary/manifest failed offline signature verification — possible compromise of the download origin (dl.vectismail.com / DNS / TLS). Investigate before running further updates.")
			os.Exit(3)
		}
		return nil
	case "rolled_back":
		if !jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), "\nUpdate failed, automatic rollback succeeded. System restored to previous state.")
			if result.Error != "" {
				fmt.Fprintf(cmd.OutOrStdout(), "Failure reason: %s\n", result.Error)
			}
		}
		os.Exit(1)
	case "rollback_failed":
		if !jsonOutput {
			fmt.Fprintln(cmd.ErrOrStderr(), "\nCRITICAL: Update failed and rollback also failed. Manual intervention required.")
			if result.Error != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", result.Error)
			}
			if result.Rollback != nil && result.Rollback.Error != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Rollback error: %s\n", result.Rollback.Error)
			}
		}
		os.Exit(2)
	default:
		if !jsonOutput {
			fmt.Fprintf(cmd.ErrOrStderr(), "Update ended with status: %s\n", result.Status)
			if result.Error != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", result.Error)
			}
		}
		os.Exit(1)
	}

	return nil
}

// pollApplyStatus polls the orchestrator status endpoint until the apply completes.
func pollApplyStatus(ctx context.Context, client *orchestrator.Client, cmd *cobra.Command, jsonOutput bool) (*orchestrator.ApplyResult, error) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	lastStep := ""

	for {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("timed out waiting for apply to complete")
		case <-ticker.C:
			status, err := client.Status(ctx)
			if err != nil {
				return nil, err
			}

			// Print step-by-step progress in human-readable mode.
			if !jsonOutput {
				for _, step := range status.Steps {
					label := fmt.Sprintf("  [%s] %s", step.Status, step.Name)
					if step.Detail != "" {
						label += " " + step.Detail
					}
					if step.Duration != "" {
						label += " (" + step.Duration + ")"
					}
					if label != lastStep && (step.Status == "done" || step.Status == "failed" || step.Status == "running") {
						fmt.Fprintln(cmd.OutOrStdout(), label)
						lastStep = label
					}
				}
			}

			// Terminal states.
			switch status.State {
			case "idle":
				// Finished (success or failure). Get final result from apply steps.
				result := &orchestrator.ApplyResult{
					Status: "success",
					Steps:  status.Steps,
				}
				if status.Error != "" {
					result.Status = "failed"
					result.Error = status.Error
				}
				return result, nil
			case "applying", "planning":
				continue
			case "rolling_back":
				if !jsonOutput && lastStep != "rolling_back" {
					fmt.Fprintln(cmd.OutOrStdout(), "\n  Automatic rollback initiated...")
					lastStep = "rolling_back"
				}
				continue
			default:
				// Unknown state; check for error.
				if status.Error != "" {
					return &orchestrator.ApplyResult{
						Status: "failed",
						Error:  status.Error,
						Steps:  status.Steps,
					}, nil
				}
			}
		}
	}
}

// --- vectis update rollback ---

func runUpdateRollback(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	client, err := newOrchestratorClient(cmd)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	if !jsonOutput {
		fmt.Fprintln(cmd.OutOrStdout(), "Rolling back to last snapshot...")
	}

	result, err := client.Rollback(ctx)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	}

	switch result.Status {
	case "success":
		if !jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), "Rollback completed successfully.")
		}
		return nil
	default:
		if !jsonOutput {
			fmt.Fprintf(cmd.ErrOrStderr(), "CRITICAL: Rollback failed. Manual intervention required.\n")
			if result.Error != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", result.Error)
			}
		}
		os.Exit(1)
	}

	return nil
}

// --- vectis update self ---

const (
	composePath        = "/etc/vectis/docker-compose.yml"
	vectisDownloadBase = "https://dl.vectismail.com"
	expectedBinaryPath = "/usr/local/bin/vectis"
)

func runUpdateSelf(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	type selfUpdateResult struct {
		Status  string `json:"status"`
		Message string `json:"message,omitempty"`
		Error   string `json:"error,omitempty"`
	}

	emitResult := func(r selfUpdateResult) {
		if jsonOutput {
			out, _ := json.MarshalIndent(r, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
		}
	}

	if !jsonOutput {
		fmt.Fprintln(cmd.OutOrStdout(), "Self-updating CLI binary and force-recreating orchestrator + API containers...")
	}

	// Step 1: Refresh the host-side CLI binary from the latest stable
	// release. Best-effort — warns and continues on failure rather than
	// blocking the container recreate, since stale-binary problems only
	// surface on the NEXT invocation. Skips when:
	//   - The running binary isn't at /usr/local/bin/vectis (custom install).
	//   - The release manifest is unreachable (offline / DNS / dl outage).
	//   - The running binary is already at the published stable version.
	// Hit during the 2026-05-08 sa1001 walkthrough — the host binary was
	// rc28 while containers were v0.1.8, and `vectis update plan` failed
	// instantly because the rc28 binary couldn't parse modern secrets.yaml.
	if !jsonOutput {
		fmt.Fprint(cmd.OutOrStdout(), "  [1/5] Refreshing CLI binary... ")
	}
	if msg, err := refreshCLIBinary(); err != nil {
		if errors.Is(err, errReleaseVerification) {
			// Fail closed: a tampered/stripped signature on the host binary is a
			// strong signal the release origin is compromised. Abort the self-update
			// before recreating containers rather than pressing on (audit U-5).
			fmt.Fprintf(cmd.ErrOrStderr(), "SECURITY: CLI binary signature verification FAILED: %v\n", err)
			fmt.Fprintln(cmd.ErrOrStderr(), "Aborting self-update — the downloaded binary/manifest could not be authenticated (possible compromise of dl.vectismail.com / DNS / TLS).")
			os.Exit(3)
		}
		if !jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), "skipped")
			fmt.Fprintf(cmd.OutOrStdout(), "    ! %s\n", err.Error())
		}
	} else {
		if !jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), msg)
		}
	}

	// Step 2: Record current image IDs for rollback.
	if !jsonOutput {
		fmt.Fprint(cmd.OutOrStdout(), "  [2/5] Recording current state... ")
	}
	orchOldImage := getCurrentImage("vectis-orchestrator")
	apiOldImage := getCurrentImage("vectis-api")
	if !jsonOutput {
		fmt.Fprintln(cmd.OutOrStdout(), "done")
	}

	// Step 3: Stop current containers.
	if !jsonOutput {
		fmt.Fprint(cmd.OutOrStdout(), "  [3/5] Stopping current containers... ")
	}
	for _, container := range []string{"vectis-orchestrator", "vectis-api"} {
		if out, err := exec.Command("docker", "stop", container).CombinedOutput(); err != nil {
			msg := fmt.Sprintf("failed to stop %s: %s", container, strings.TrimSpace(string(out)))
			if !jsonOutput {
				fmt.Fprintln(cmd.OutOrStdout(), "FAILED")
				fmt.Fprintf(cmd.ErrOrStderr(), "  Error: %s\n", msg)
			}
			emitResult(selfUpdateResult{Status: "failed", Error: msg})
			os.Exit(1)
		}
	}
	if !jsonOutput {
		fmt.Fprintln(cmd.OutOrStdout(), "done")
	}

	// Step 4: Start new containers via docker compose.
	if !jsonOutput {
		fmt.Fprint(cmd.OutOrStdout(), "  [4/5] Starting new containers... ")
	}
	if out, err := exec.Command("docker", "compose", "-f", composePath, "up", "-d",
		"orchestrator", "api").CombinedOutput(); err != nil {
		msg := fmt.Sprintf("failed to start containers: %s", strings.TrimSpace(string(out)))
		if !jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), "FAILED")
			fmt.Fprintf(cmd.ErrOrStderr(), "  Error: %s\n", msg)
			fmt.Fprintln(cmd.ErrOrStderr(), "  Attempting rollback...")
		}
		revertSelf(cmd, orchOldImage, apiOldImage, jsonOutput)
		emitResult(selfUpdateResult{Status: "failed", Error: msg})
		os.Exit(1)
	}
	if !jsonOutput {
		fmt.Fprintln(cmd.OutOrStdout(), "done")
	}

	// Step 5: Health checks.
	if !jsonOutput {
		fmt.Fprint(cmd.OutOrStdout(), "  [5/5] Running health checks... ")
	}
	if err := waitForContainerHealth("vectis-orchestrator", 60*time.Second); err != nil {
		msg := fmt.Sprintf("orchestrator health check failed: %s", err)
		if !jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), "FAILED")
			fmt.Fprintf(cmd.ErrOrStderr(), "  Error: %s\n", msg)
			fmt.Fprintln(cmd.ErrOrStderr(), "  Attempting rollback...")
		}
		revertSelf(cmd, orchOldImage, apiOldImage, jsonOutput)
		emitResult(selfUpdateResult{Status: "failed", Error: msg})
		os.Exit(1)
	}
	if err := waitForContainerHealth("vectis-api", 60*time.Second); err != nil {
		msg := fmt.Sprintf("API health check failed: %s", err)
		if !jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), "FAILED")
			fmt.Fprintf(cmd.ErrOrStderr(), "  Error: %s\n", msg)
			fmt.Fprintln(cmd.ErrOrStderr(), "  Attempting rollback...")
		}
		revertSelf(cmd, orchOldImage, apiOldImage, jsonOutput)
		emitResult(selfUpdateResult{Status: "failed", Error: msg})
		os.Exit(1)
	}
	if !jsonOutput {
		fmt.Fprintln(cmd.OutOrStdout(), "all healthy")
		fmt.Fprintln(cmd.OutOrStdout(), "\nSelf-update completed successfully.")
	}

	emitResult(selfUpdateResult{Status: "success", Message: "Self-update completed successfully"})
	return nil
}

// getCurrentImage returns the image tag currently used by a running container.
func getCurrentImage(containerName string) string {
	image, _ := dockerInspect(containerName, "{{.Config.Image}}")
	return image
}

// waitForContainerHealth waits until a container reports healthy or the timeout expires.
func waitForContainerHealth(containerName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := dockerInspect(containerName,
			"{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}")
		if err == nil {
			parts := strings.Split(out, "|")
			if len(parts) >= 2 {
				state := parts[0]
				health := parts[1]
				if state == "running" && (health == "healthy" || health == "none") {
					return nil
				}
				if state == "exited" || state == "dead" {
					return fmt.Errorf("container %s is %s", containerName, state)
				}
			}
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("container %s did not become healthy within %s", containerName, timeout)
}

// revertSelf attempts to roll back a failed self-update by restarting the old containers.
func revertSelf(cmd *cobra.Command, orchImage, apiImage string, jsonOutput bool) {
	if !jsonOutput {
		fmt.Fprint(cmd.OutOrStdout(), "  Reverting to previous images... ")
	}

	// Stop any partially started new containers.
	for _, container := range []string{"vectis-orchestrator", "vectis-api"} {
		exec.Command("docker", "stop", container).Run()
		exec.Command("docker", "rm", "-f", container).Run()
	}

	// Restart with old images via docker compose.
	out, err := exec.Command("docker", "compose", "-f", composePath, "up", "-d",
		"orchestrator", "api").CombinedOutput()
	if err != nil {
		if !jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), "FAILED")
			fmt.Fprintf(cmd.ErrOrStderr(), "  CRITICAL: Rollback failed: %s\n", strings.TrimSpace(string(out)))
			fmt.Fprintln(cmd.ErrOrStderr(), "  Manual intervention required. Previous images:")
			fmt.Fprintf(cmd.ErrOrStderr(), "    orchestrator: %s\n", orchImage)
			fmt.Fprintf(cmd.ErrOrStderr(), "    api:          %s\n", apiImage)
		}
		return
	}

	if !jsonOutput {
		fmt.Fprintln(cmd.OutOrStdout(), "done")
		fmt.Fprintln(cmd.OutOrStdout(), "  Self-update rolled back successfully.")
	}
}

// refreshCLIBinary downloads the latest stable vectis binary from
// dl.vectismail.com and atomically replaces /usr/local/bin/vectis when its
// version differs from the running process's version. Returns a short
// human-readable status message on success ("updated v0.1.6 -> v0.1.8" /
// "already at v0.1.8") and a non-nil error explaining why the refresh
// was skipped on any failure (best-effort: callers must not treat the
// error as fatal).
// errReleaseVerification marks a failure of the offline Ed25519 signature gate
// (a tampered signature, or a stripped/missing signature while a public key IS
// embedded) — the strongest active-attack signal on the self-update path. It is
// deliberately DISTINCT from a benign skip (offline, custom install path, or a
// build with no embedded key): callers unwrap it with errors.Is to surface an
// alert loudly and exit non-zero, so automation can tell tampering apart from a
// network blip (audit U-5).
var errReleaseVerification = errors.New("release signature verification failed")

// classifyVerifyErr wraps a releasesign.Verify result so the caller can
// distinguish attack from benign-skip. A nil error stays nil; ErrNotConfigured
// (this build has no embedded key) is a benign skip; anything else is a genuine
// verification failure tagged with errReleaseVerification.
func classifyVerifyErr(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, releasesign.ErrNotConfigured):
		return fmt.Errorf("release signature check unavailable: %w", err)
	default:
		return fmt.Errorf("%w: %v", errReleaseVerification, err)
	}
}

// httpGetBody GETs url and returns up to limit bytes of the body plus whether the
// status was 200. A transport failure returns a non-nil error; a non-200 status
// returns ok=false with a nil error so the caller can classify it (e.g. a
// stripped signature is attack-class only when a key is embedded).
func httpGetBody(client *http.Client, url string, limit int64) (body []byte, ok bool, err error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false, nil
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return b, true, err
}

func refreshCLIBinary() (string, error) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return "", fmt.Errorf("only linux/amd64 binaries are published; running on %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate running binary: %w", err)
	}
	resolved, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		resolved = exePath
	}
	if resolved != expectedBinaryPath {
		return "", fmt.Errorf("running binary is at %s; only %s is auto-refreshed", resolved, expectedBinaryPath)
	}

	httpClient := &http.Client{Timeout: 30 * time.Second}

	// 1. Discover the latest stable release — and AUTHENTICATE the manifest before
	// trusting the tag it names (audit U-3). Previously this step chose which
	// signed binary to install from an UNsigned, un-allowlisted manifest, so a
	// forged/replayed releases-stable.json could name an older, still-validly-
	// signed release and force a downgrade — the binary signature at 3b blocks
	// RCE, not rollback. We now verify the manifest's Ed25519 signature, allowlist
	// the tag, bind the channel, and refuse anything not strictly newer, mirroring
	// the orchestrator's manifest trust boundary.
	stableURL := vectisDownloadBase + "/releases-stable.json"
	manifestBytes, ok, err := httpGetBody(httpClient, stableURL, 64*1024)
	if err != nil {
		return "", fmt.Errorf("fetch releases-stable.json: %w", err)
	}
	if !ok {
		return "", fmt.Errorf("releases-stable.json fetch failed (non-200)")
	}
	sigManifest, sok, err := httpGetBody(httpClient, stableURL+".ed25519", 4*1024)
	if err != nil {
		return "", fmt.Errorf("fetch releases-stable.json signature: %w", err)
	}
	if !sok {
		if releasesign.Configured() {
			return "", fmt.Errorf("releases-stable.json signature missing (refusing unsigned release selector): %w", errReleaseVerification)
		}
		return "", fmt.Errorf("releases-stable.json signature unavailable")
	}
	if err := classifyVerifyErr(releasesign.Verify(manifestBytes, string(sigManifest))); err != nil {
		return "", fmt.Errorf("releases-stable.json signature: %w", err)
	}

	var manifest struct {
		Latest       string `json:"latest"`
		Channel      string `json:"channel"`
		BinarySHA256 string `json:"binary_sha256"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		return "", fmt.Errorf("decode releases-stable.json: %w", err)
	}
	if manifest.Latest == "" {
		return "", fmt.Errorf("releases-stable.json missing 'latest' field")
	}
	if !orchestrator.ValidReleaseTag(manifest.Latest) {
		return "", fmt.Errorf("releases-stable.json `latest` = %q is not a valid release tag", manifest.Latest)
	}
	if want := orchestrator.ExpectedChannelForURL(stableURL); want != "" && manifest.Channel != want {
		return "", fmt.Errorf("releases-stable.json channel mismatch: want %q, got %q", want, manifest.Channel)
	}

	// Anti-rollback: never self-update to an older-or-equal binary (audit U-2/U-3).
	// version.Version is "dev" in local builds, so fall back to string equality
	// when it isn't a comparable release tag.
	if orchestrator.ValidReleaseTag(version.Version) {
		cmp, cerr := orchestrator.CompareReleaseTags(manifest.Latest, version.Version)
		if cerr != nil {
			return "", fmt.Errorf("compare release tags: %w", cerr)
		}
		if cmp <= 0 {
			return fmt.Sprintf("already at %s (no newer stable release)", version.Version), nil
		}
	} else if manifest.Latest == version.Version {
		return fmt.Sprintf("already at %s", manifest.Latest), nil
	}

	// 2. Download binary + checksum + release signature.
	binURL := fmt.Sprintf("%s/%s/vectis-linux-amd64", vectisDownloadBase, manifest.Latest)
	shaURL := binURL + ".sha256"
	sigURL := binURL + ".ed25519"

	tmpDir, err := os.MkdirTemp("", "vectis-update-")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	tmpBin := filepath.Join(tmpDir, "vectis.new")

	if err := downloadFile(httpClient, binURL, tmpBin); err != nil {
		return "", fmt.Errorf("download %s: %w", binURL, err)
	}

	// Bound the checksum fetch (a .sha256 is 64 hex chars + a filename). The old
	// io.ReadAll(shaResp.Body) was unbounded, so a hostile/broken origin's
	// oversized 200 body could exhaust memory before the signature gate (same
	// class as the binary-download bound below). httpGetBody caps the read and
	// reports a non-200 as ok=false.
	shaBytes, shaOK, err := httpGetBody(httpClient, shaURL, 4096)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", shaURL, err)
	}
	if !shaOK {
		return "", fmt.Errorf("%s returned a non-200 status", shaURL)
	}
	// Guard the field split: an empty/whitespace-only body (a hostile or broken
	// origin serving a 200 with no checksum) must not panic on [0] (REL-2). This
	// runs before the signature gate, so it cannot admit a bad binary — but an
	// unhandled index-out-of-range would crash `vectis update`.
	shaFields := strings.Fields(string(shaBytes))
	if len(shaFields) == 0 {
		return "", fmt.Errorf("%s returned an empty checksum body", shaURL)
	}
	expectedSHA := strings.TrimSpace(shaFields[0])

	// 3. Verify checksum (transport-integrity only — same origin as the binary,
	// so it defends against a truncated download, not a hostile origin).
	binBytes, err := os.ReadFile(tmpBin)
	if err != nil {
		return "", fmt.Errorf("read downloaded binary: %w", err)
	}
	actualSHA := hex.EncodeToString(sha256Sum(binBytes))
	if actualSHA != expectedSHA {
		return "", fmt.Errorf("checksum mismatch (expected %s, got %s)", expectedSHA, actualSHA)
	}

	// 3a. Bind the downloaded bytes to the SIGNED manifest (REL-1). The .sha256
	// above is same-origin (transport integrity only), and the Ed25519 binary
	// signature at 3b authenticates the bytes but carries NO version metadata — so
	// under an origin/DNS/TLS compromise an attacker can replay the genuine
	// current manifest (newest tag → passes the anti-rollback check at step 1)
	// while serving an OLDER but still-validly-signed binary + its real
	// .sha256/.ed25519, forcing a downgrade to any prior signed release. The
	// manifest's binary_sha256 is authenticated by the manifest's Ed25519
	// signature (verified at step 1) and names THIS release's exact bytes, so
	// requiring the download to match it closes that downgrade. FAIL CLOSED,
	// attack-class (errReleaseVerification). Enforce-IF-present: manifests
	// published before REL-1 (live v0.1.42) omit the field, so an unconditional
	// check would break the next update — and a stripped field cannot weaken a
	// v0.1.43+ client, because the signature covers the field (an attacker cannot
	// strip it from a signed manifest) and every genuine fieldless manifest names
	// a tag <= v0.1.42, which the anti-rollback check already refuses.
	if err := verifyManifestBinaryDigest(manifest.BinarySHA256, actualSHA); err != nil {
		return "", err
	}

	// 3b. Verify the offline Ed25519 release signature over the binary before
	// installing it (audit E-H3). This is the real supply-chain gate: unlike the
	// same-origin SHA256, the signature cannot be forged by a compromise of
	// dl.vectismail.com / DNS / TLS — only the holder of the offline release key
	// can produce it. FAIL CLOSED: a missing, unreadable, or invalid signature
	// (or a binary built without an embedded public key) refuses the install
	// rather than swapping in an unverified binary at /usr/local/bin/vectis.
	sigBytes, sigOK, err := httpGetBody(httpClient, sigURL, 4096)
	if err != nil {
		return "", fmt.Errorf("download release signature %s: %w", sigURL, err)
	}
	if !sigOK {
		if releasesign.Configured() {
			return "", fmt.Errorf("release signature %s missing (refusing unsigned self-update): %w", sigURL, errReleaseVerification)
		}
		return "", fmt.Errorf("release signature %s unavailable", sigURL)
	}
	if err := classifyVerifyErr(releasesign.Verify(binBytes, string(sigBytes))); err != nil {
		return "", fmt.Errorf("release signature for %s: %w", binURL, err)
	}

	// 4. Make executable and install into place. Linux allows renaming a
	// file over a running binary's path — the kernel keeps the old inode
	// mapped for the running process; subsequent invocations pick up the
	// new binary.
	if err := os.Chmod(tmpBin, 0o755); err != nil {
		return "", fmt.Errorf("chmod downloaded binary: %w", err)
	}
	if err := installBinary(tmpBin, expectedBinaryPath); err != nil {
		return "", err
	}

	return fmt.Sprintf("updated %s -> %s (takes effect on next vectis invocation)", version.Version, manifest.Latest), nil
}

// verifyManifestBinaryDigest gates a downloaded binary against the sha256 the
// SIGNED release manifest names for this release (REL-1). manifestDigest is the
// manifest's `binary_sha256`; actualSHA is the hex sha256 of the downloaded
// bytes (already checked against the same-origin .sha256 by the caller).
//
// Enforce-IF-present: an empty manifestDigest (a pre-REL-1 manifest or a
// self-hosted mirror) is a benign skip — the caller still gates the install on
// the per-binary Ed25519 signature. A malformed or mismatching digest is
// attack-class (errReleaseVerification): a mismatch means the served bytes are
// not the ones the signed manifest names, i.e. a tampered/downgraded binary.
func verifyManifestBinaryDigest(manifestDigest, actualSHA string) error {
	if manifestDigest == "" {
		return nil
	}
	if !orchestrator.ValidBinaryDigest(manifestDigest) {
		return fmt.Errorf("%w: releases manifest binary_sha256 = %q is not a valid sha256 digest", errReleaseVerification, manifestDigest)
	}
	if actualSHA != manifestDigest {
		return fmt.Errorf("%w: downloaded binary sha256 %s does not match the signed manifest digest %s (refusing possible downgrade)", errReleaseVerification, actualSHA, manifestDigest)
	}
	return nil
}

// installBinary moves the freshly-downloaded, checksum-verified binary into
// place at dest.
//
// The fast path is a direct atomic rename, which succeeds when the caller owns
// dest (e.g. running as root) and src/dest share a filesystem. When an operator
// runs `vectis update apply` as an ordinary user — the common case, since the
// orchestrator drives the container swap and only this host binary needs root
// to replace — that rename fails with EACCES on root-owned /usr/local/bin.
//
// Rather than surface a bare "permission denied", fall back to a
// NON-INTERACTIVE privileged copy via `sudo -n install`. `sudo -n` never blocks
// on a password prompt, which keeps both the interactive and --json/automation
// callers safe:
//   - NOPASSWD sudo (build boxes, CI, many prod setups): the refresh just works.
//   - password-gated sudo: `sudo -n` fails fast and we return an actionable
//     error telling the operator exactly how to refresh manually.
//
// `install` also copies across filesystems, so this doubles as the fix for a
// cross-device rename. dest is a fixed constant and src is a path we control, so
// there is no shell or argument-injection surface.
func installBinary(src, dest string) error {
	if err := os.Rename(src, dest); err == nil {
		return nil
	}

	if sudoPath, err := exec.LookPath("sudo"); err == nil {
		if err := exec.Command(sudoPath, "-n", "install", "-m", "0755", src, dest).Run(); err == nil {
			return nil
		}
	}

	return fmt.Errorf("cannot write %s without privileges — run 'sudo vectis update self' "+
		"to refresh the host CLI binary", dest)
}

// maxBinaryDownload bounds the self-update binary fetch. The vectis binary is
// tens of MB; 512 MiB is a generous ceiling that still refuses a hostile origin
// streaming an unbounded body to exhaust host disk before the signature gate
// runs (REL-4). Every other release fetch is already length-bounded.
// var (not const) so tests can lower the cap without moving 512 MiB.
var maxBinaryDownload int64 = 512 << 20 // 512 MiB

func downloadFile(client *http.Client, url, dest string) error {
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	f, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer f.Close()
	// Copy at most maxBinaryDownload+1 so an oversize body is rejected explicitly
	// rather than silently truncated (a truncated binary would otherwise only be
	// caught later by the checksum/signature gate).
	n, err := io.Copy(f, io.LimitReader(resp.Body, maxBinaryDownload+1))
	if err != nil {
		os.Remove(dest) // don't leave a partial download behind
		return err
	}
	if n > maxBinaryDownload {
		os.Remove(dest)
		return fmt.Errorf("download exceeds %d bytes (refusing)", maxBinaryDownload)
	}
	return nil
}

func sha256Sum(b []byte) []byte {
	h := sha256.New()
	h.Write(b)
	return h.Sum(nil)
}

func init() {
	updateApplyCmd.Flags().BoolVar(&updateForce, "force", false, "Plan and apply in one step (skip separate plan)")

	updateCmd.AddCommand(updatePlanCmd)
	updateCmd.AddCommand(updateApplyCmd)
	updateCmd.AddCommand(updateRollbackCmd)
	updateCmd.AddCommand(updateSelfCmd)
	RootCmd.AddCommand(updateCmd)
}
