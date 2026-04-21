package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/orchestrator"
	vectistls "github.com/Veltara-Works/vectis/internal/tls"
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
	Short: "Update the orchestrator and API containers",
	Long:  "Self-update bypasses the orchestrator. It pulls new orchestrator and API images from GHCR, restarts those containers, and verifies health.",
	RunE:  runUpdateSelf,
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
		return nil
	}

	fmt.Fprintln(cmd.OutOrStdout(), "Update plan generated:")
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
	ghcrOrchestrator = "ghcr.io/veltara-works/vectis-orchestrator"
	ghcrAPI          = "ghcr.io/veltara-works/vectis-api"
	composePath      = "/etc/vectis/docker-compose.yml"
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
		fmt.Fprintln(cmd.OutOrStdout(), "Self-updating orchestrator and API containers...")
	}

	// Step 1: Pull latest images.
	if !jsonOutput {
		fmt.Fprint(cmd.OutOrStdout(), "  [1/5] Pulling new images... ")
	}
	for _, image := range []string{ghcrOrchestrator + ":latest", ghcrAPI + ":latest"} {
		if out, err := exec.Command("docker", "pull", image).CombinedOutput(); err != nil {
			msg := fmt.Sprintf("failed to pull %s: %s", image, strings.TrimSpace(string(out)))
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

func init() {
	updateApplyCmd.Flags().BoolVar(&updateForce, "force", false, "Plan and apply in one step (skip separate plan)")

	updateCmd.AddCommand(updatePlanCmd)
	updateCmd.AddCommand(updateApplyCmd)
	updateCmd.AddCommand(updateRollbackCmd)
	updateCmd.AddCommand(updateSelfCmd)
	RootCmd.AddCommand(updateCmd)
}
