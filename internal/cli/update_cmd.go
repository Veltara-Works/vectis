package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
		if !jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), "\nUpdate applied successfully.")
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
	out, err := exec.Command("docker", "inspect", "--format", "{{.Config.Image}}", containerName).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// waitForContainerHealth waits until a container reports healthy or the timeout expires.
func waitForContainerHealth(containerName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("docker", "inspect", "--format",
			"{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}",
			containerName).Output()
		if err == nil {
			parts := strings.Split(strings.TrimSpace(string(out)), "|")
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

	// 1. Discover the latest stable tag.
	resp, err := httpClient.Get(vectisDownloadBase + "/releases-stable.json")
	if err != nil {
		return "", fmt.Errorf("fetch releases-stable.json: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("releases-stable.json returned HTTP %d", resp.StatusCode)
	}
	var manifest struct {
		Latest string `json:"latest"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		return "", fmt.Errorf("decode releases-stable.json: %w", err)
	}
	if manifest.Latest == "" {
		return "", fmt.Errorf("releases-stable.json missing 'latest' field")
	}

	if manifest.Latest == version.Version {
		return fmt.Sprintf("already at %s", manifest.Latest), nil
	}

	// 2. Download binary + checksum.
	binURL := fmt.Sprintf("%s/%s/vectis-linux-amd64", vectisDownloadBase, manifest.Latest)
	shaURL := binURL + ".sha256"

	tmpDir, err := os.MkdirTemp("", "vectis-update-")
	if err != nil {
		return "", fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)
	tmpBin := filepath.Join(tmpDir, "vectis.new")

	if err := downloadFile(httpClient, binURL, tmpBin); err != nil {
		return "", fmt.Errorf("download %s: %w", binURL, err)
	}

	shaResp, err := httpClient.Get(shaURL)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", shaURL, err)
	}
	shaBytes, err := io.ReadAll(shaResp.Body)
	shaResp.Body.Close()
	if err != nil {
		return "", fmt.Errorf("read %s: %w", shaURL, err)
	}
	if shaResp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s returned HTTP %d", shaURL, shaResp.StatusCode)
	}
	expectedSHA := strings.TrimSpace(strings.Fields(string(shaBytes))[0])

	// 3. Verify checksum.
	binBytes, err := os.ReadFile(tmpBin)
	if err != nil {
		return "", fmt.Errorf("read downloaded binary: %w", err)
	}
	actualSHA := hex.EncodeToString(sha256Sum(binBytes))
	if actualSHA != expectedSHA {
		return "", fmt.Errorf("checksum mismatch (expected %s, got %s)", expectedSHA, actualSHA)
	}

	// 4. Make executable and atomic-rename into place. Linux allows
	// renaming a file over a running binary's path — the kernel keeps the
	// old inode mapped for the running process; subsequent invocations
	// pick up the new binary.
	if err := os.Chmod(tmpBin, 0o755); err != nil {
		return "", fmt.Errorf("chmod downloaded binary: %w", err)
	}
	if err := os.Rename(tmpBin, expectedBinaryPath); err != nil {
		return "", fmt.Errorf("install binary at %s: %w", expectedBinaryPath, err)
	}

	return fmt.Sprintf("updated %s -> %s (takes effect on next vectis invocation)", version.Version, manifest.Latest), nil
}

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
	_, err = io.Copy(f, resp.Body)
	return err
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
