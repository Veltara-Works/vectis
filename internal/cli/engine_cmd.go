package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/engine"
	"github.com/Veltara-Works/vectis/internal/logging"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/spf13/cobra"
)

var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate all service configuration files",
	Long: `Read config.yaml, secrets.yaml, and domain data from Postgres,
then render all service configuration templates to the output directory.`,
	RunE: runGenerate,
}

var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show pending configuration changes",
	Long:  `Compare generated configs against what is currently deployed.`,
	RunE:  runDiff,
}

var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply configuration changes and reload services",
	Long: `Regenerate configs, write them to disk, and reload/restart
services as needed based on what changed.`,
	RunE: runApply,
}

var outputDir string

func runGenerate(cmd *cobra.Command, args []string) error {
	data, err := loadTemplateData(cmd)
	if err != nil {
		return err
	}

	files, err := engine.Generate(data)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error generating configs: %s\n", err)
		os.Exit(1)
	}

	if err := engine.WriteFiles(outputDir, files); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error writing configs: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Generated %d config files to %s\n", len(files), outputDir)
	for _, f := range files {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", f.RelPath)
	}
	return nil
}

func runDiff(cmd *cobra.Command, args []string) error {
	data, err := loadTemplateData(cmd)
	if err != nil {
		return err
	}

	files, err := engine.Generate(data)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error generating configs: %s\n", err)
		os.Exit(1)
	}

	diffs, err := engine.DiffFiles(outputDir, files)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error diffing configs: %s\n", err)
		os.Exit(1)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")

	if len(diffs) == 0 {
		if jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), "[]")
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "No configuration changes pending")
		}
		return nil
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(diffs, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "%d file(s) changed:\n", len(diffs))
		for _, d := range diffs {
			fmt.Fprintf(cmd.OutOrStdout(), "  [%s] %s\n", d.Status, d.RelPath)
		}
	}
	return nil
}

func runApply(cmd *cobra.Command, args []string) error {
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	jsonOutput, _ := cmd.Flags().GetBool("json")

	data, err := loadTemplateData(cmd)
	if err != nil {
		return err
	}

	files, err := engine.Generate(data)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error generating configs: %s\n", err)
		os.Exit(1)
	}

	// Compute diff to determine what changed.
	diffs, err := engine.DiffFiles(outputDir, files)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error computing diff: %s\n", err)
		os.Exit(1)
	}

	if len(diffs) == 0 {
		if jsonOutput {
			fmt.Fprintln(cmd.OutOrStdout(), `{"changes":[],"actions":[],"results":[]}`)
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "No configuration changes to apply.")
		}
		return nil
	}

	// Determine which services need reload/restart.
	actions := engine.DetermineActions(diffs)

	if dryRun {
		if jsonOutput {
			type dryRunOutput struct {
				Changes []engine.FileDiff       `json:"changes"`
				Actions []engine.ServiceAction  `json:"actions"`
			}
			out, _ := json.MarshalIndent(dryRunOutput{Changes: diffs, Actions: actions}, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "%d file(s) changed:\n", len(diffs))
			for _, d := range diffs {
				fmt.Fprintf(cmd.OutOrStdout(), "  [%s] %s\n", d.Status, d.RelPath)
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Service actions required:")
			for _, a := range actions {
				line := fmt.Sprintf("  %-12s %s", a.Service+":", a.Action)
				if a.Reason != "" {
					line += fmt.Sprintf("  (%s)", a.Reason)
				}
				fmt.Fprintln(cmd.OutOrStdout(), line)
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Run without --dry-run to apply.")
		}
		return nil
	}

	// Write config files.
	if err := engine.WriteFiles(outputDir, files); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error writing configs: %s\n", err)
		os.Exit(1)
	}

	if !jsonOutput {
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote %d config files to %s\n", len(files), outputDir)
	}

	// Execute reload/restart actions.
	results := engine.ExecuteActions(actions)

	failures := 0
	if jsonOutput {
		type applyOutput struct {
			Changes []engine.FileDiff       `json:"changes"`
			Actions []engine.ServiceAction  `json:"actions"`
			Results []engine.ReloadResult   `json:"results"`
		}
		out, _ := json.MarshalIndent(applyOutput{
			Changes: diffs, Actions: actions, Results: results,
		}, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		if len(results) > 0 {
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Service actions:")
		}
		for _, r := range results {
			icon := "✓"
			if !r.Success {
				icon = "✗"
				failures++
			}
			fmt.Fprintf(cmd.OutOrStdout(), "  %s %-12s %s\n", icon, r.Service, r.Action)
			if r.Error != "" {
				fmt.Fprintf(cmd.ErrOrStderr(), "    Error: %s\n", r.Error)
			}
		}
		if len(results) == 0 {
			fmt.Fprintln(cmd.OutOrStdout(), "\nNo service actions required.")
		}
	}

	if failures > 0 {
		os.Exit(1)
	}

	if !jsonOutput {
		fmt.Fprintln(cmd.OutOrStdout(), "\nConfiguration applied successfully.")
	}
	return nil
}

func loadTemplateData(cmd *cobra.Command) (*engine.TemplateData, error) {
	configDir, _ := cmd.Flags().GetString("config-dir")

	cfg, secrets, err := config.LoadAll(configDir)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	// Connect to Postgres to fetch domains for DKIM config.
	// --db-host overrides the secrets host for the connection (useful when
	// generating from the host but templates target Docker service names).
	logger := logging.NewLogger("warn")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	dbHost := secrets.Database.Host
	if override, _ := cmd.Flags().GetString("db-host"); override != "" {
		dbHost = override
	}
	dbCfg := database.ConfigFromSecrets(
		dbHost, secrets.Database.Port, secrets.Database.Name,
		secrets.Database.APIUser, secrets.Database.APIPassword,
	)
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: database connection failed: %s\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	domainRepo := repository.NewDomainRepo(pool)
	domains, err := domainRepo.List(ctx, nil)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: failed to fetch domains: %s\n", err)
		os.Exit(1)
	}

	return engine.NewTemplateData(cfg, secrets, domains), nil
}

func init() {
	generateCmd.Flags().StringVarP(&outputDir, "output", "o", "/var/vectis/generated", "Output directory for generated configs")
	generateCmd.Flags().String("db-host", "", "Override database host for connection (templates still use secrets.yaml value)")
	diffCmd.Flags().StringVarP(&outputDir, "output", "o", "/var/vectis/generated", "Output directory to compare against")
	diffCmd.Flags().String("db-host", "", "Override database host for connection")

	applyCmd.Flags().StringVarP(&outputDir, "output", "o", "/var/vectis/generated", "Output directory for generated configs")
	applyCmd.Flags().String("db-host", "", "Override database host for connection")
	applyCmd.Flags().Bool("dry-run", false, "Show what would change without applying")

	configCmd.AddCommand(generateCmd)
	configCmd.AddCommand(diffCmd)
	configCmd.AddCommand(applyCmd)
}
