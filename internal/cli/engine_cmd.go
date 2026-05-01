package cli

import (
	"context"
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

var generateOutputDir string

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

	if err := engine.WriteFiles(generateOutputDir, files); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error writing configs: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(cmd.OutOrStdout(), "Generated %d config files to %s\n", len(files), generateOutputDir)
	for _, f := range files {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", f.RelPath)
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

	data := engine.NewTemplateData(cfg, secrets, domains)
	// Per-domain spam list entries (Pro: advanced_spam). Loaded best-effort —
	// the table only exists post-migration 000016, so a "relation does not
	// exist" failure during a pre-migration generate is logged and ignored,
	// not fatal. The map files render empty; the rspamd Lua extension stays
	// a no-op until entries are added.
	spamRepo := repository.NewSpamListRepo(pool)
	if entries, err := spamRepo.ListAll(ctx); err == nil {
		data.SpamListEntries = make([]engine.SpamListInfo, 0, len(entries))
		for _, e := range entries {
			data.SpamListEntries = append(data.SpamListEntries, engine.SpamListInfo{
				DomainName: e.DomainName,
				Kind:       e.Kind,
				Scope:      e.Scope,
				Pattern:    e.Pattern,
			})
		}
	} else {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to load spam list entries (skipping advanced spam config): %s\n", err)
	}
	return data, nil
}

func init() {
	generateCmd.Flags().StringVarP(&generateOutputDir, "output", "o", "/var/vectis/generated", "Output directory for generated configs")
	generateCmd.Flags().String("db-host", "", "Override database host for connection (templates still use secrets.yaml value)")

	configCmd.AddCommand(generateCmd)
}
