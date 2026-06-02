package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/engine"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// configCmd is the parent command for configuration-related subcommands.
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Configuration management commands",
}

// validateCmd loads config.yaml and secrets.yaml from --config-dir,
// runs validation, and reports the results.
var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "Validate configuration and secrets files",
	Long: `Load config.yaml and secrets.yaml from the configuration directory,
parse them with strict field checking, and report any errors.

Exit codes:
  0  Configuration is valid
  1  File error (missing file, unreadable, bad YAML syntax)
  2  Validation errors (invalid field values)`,
	RunE: runValidate,
}

// diffCmd compares generated configs against what's on disk.
var diffCmd = &cobra.Command{
	Use:   "diff",
	Short: "Show pending configuration changes",
	Long: `Load config.yaml, secrets.yaml, and query Postgres for domains,
generate expected config files, and compare against what's currently
on disk at the output directory.

Exit codes:
  0  No changes pending
  1  Changes pending
  2  Validation error`,
	RunE: runDiff,
}

// applyCmd generates and writes config files, then reloads/restarts services.
var applyCmd = &cobra.Command{
	Use:   "apply",
	Short: "Apply configuration changes",
	Long: `Load config.yaml, secrets.yaml, and query Postgres for domains,
generate config files, write them to the output directory, and
reload/restart services as needed.

Exit codes:
  0  Success (all files written, all services reloaded)
  1  Partial failure (some service actions failed)
  2  Validation error`,
	RunE: runApply,
}

// defaultOutputDir is the default directory for generated config files.
const defaultOutputDir = "/var/vectis/generated"

// validateResult is the JSON-serialisable output of the validate command.
type validateResult struct {
	Valid  bool            `json:"valid"`
	Errors []validateError `json:"errors,omitempty"`
}

type validateError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func runValidate(cmd *cobra.Command, args []string) error {
	configDir, err := cmd.Flags().GetString("config-dir")
	if err != nil {
		return err
	}
	jsonOutput, err := cmd.Flags().GetBool("json")
	if err != nil {
		return err
	}

	// Load both files. A file-level error (missing, unreadable, bad YAML)
	// is reported immediately and exits with code 1.
	cfg, secrets, err := config.LoadAll(configDir)
	if err != nil {
		if jsonOutput {
			result := validateResult{
				Valid: false,
				Errors: []validateError{
					{Field: "file", Message: err.Error()},
				},
			}
			out, _ := json.MarshalIndent(result, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		}
		os.Exit(1)
		return nil // unreachable, but keeps the compiler happy
	}

	// Run semantic validation on the loaded configuration.
	var errs []validateError
	errs = append(errs, validateConfig(cfg)...)
	errs = append(errs, validateSecrets(secrets)...)

	if len(errs) > 0 {
		if jsonOutput {
			result := validateResult{Valid: false, Errors: errs}
			out, _ := json.MarshalIndent(result, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Configuration has %d validation error(s):\n", len(errs))
			for _, e := range errs {
				fmt.Fprintf(cmd.ErrOrStderr(), "  - %s: %s\n", e.Field, e.Message)
			}
		}
		os.Exit(2)
		return nil
	}

	// All good.
	if jsonOutput {
		result := validateResult{Valid: true}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "Configuration is valid")
	}
	return nil
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

func validateConfig(cfg *config.VectisConfig) []validateError {
	var errs []validateError

	if cfg.Hostname == "" {
		errs = append(errs, validateError{
			Field:   "hostname",
			Message: "must not be empty",
		})
	}

	// TLS
	switch cfg.TLS.Provider {
	case "letsencrypt":
		if cfg.TLS.Email == "" {
			errs = append(errs, validateError{
				Field:   "tls.email",
				Message: "required when tls.provider is letsencrypt",
			})
		}
	case "custom":
		if cfg.TLS.CertPath == "" {
			errs = append(errs, validateError{
				Field:   "tls.cert_path",
				Message: "required when tls.provider is custom",
			})
		}
		if cfg.TLS.KeyPath == "" {
			errs = append(errs, validateError{
				Field:   "tls.key_path",
				Message: "required when tls.provider is custom",
			})
		}
	case "":
		errs = append(errs, validateError{
			Field:   "tls.provider",
			Message: "must not be empty (use letsencrypt or custom)",
		})
	default:
		errs = append(errs, validateError{
			Field:   "tls.provider",
			Message: fmt.Sprintf("unknown provider %q (use letsencrypt or custom)", cfg.TLS.Provider),
		})
	}

	// Resources profile
	switch cfg.Resources.Profile {
	case "dev", "small", "production", "enterprise":
		// ok
	default:
		errs = append(errs, validateError{
			Field:   "resources.profile",
			Message: fmt.Sprintf("unknown profile %q (use dev, small, production, or enterprise)", cfg.Resources.Profile),
		})
	}

	// ClamAV profile
	switch cfg.ClamAV.Profile {
	case "none", "dev", "small", "production", "enterprise":
		// ok
	default:
		errs = append(errs, validateError{
			Field:   "clamav.profile",
			Message: fmt.Sprintf("unknown profile %q (use none, dev, small, production, or enterprise)", cfg.ClamAV.Profile),
		})
	}

	// Rspamd thresholds
	if cfg.Rspamd.SpamThreshold <= 0 {
		errs = append(errs, validateError{
			Field:   "rspamd.spam_threshold",
			Message: "must be greater than 0",
		})
	}
	if cfg.Rspamd.RejectThreshold <= 0 {
		errs = append(errs, validateError{
			Field:   "rspamd.reject_threshold",
			Message: "must be greater than 0",
		})
	}

	// Postfix
	if cfg.Postfix.MessageSizeLimit <= 0 {
		errs = append(errs, validateError{
			Field:   "postfix.message_size_limit",
			Message: "must be greater than 0",
		})
	}

	// Dovecot
	if cfg.Dovecot.MailLocation == "" {
		errs = append(errs, validateError{
			Field:   "dovecot.mail_location",
			Message: "must not be empty",
		})
	}
	if cfg.Dovecot.QuotaDefaultMB <= 0 {
		errs = append(errs, validateError{
			Field:   "dovecot.quota_default_mb",
			Message: "must be greater than 0",
		})
	}

	// Backup
	if cfg.Backup.Enabled && cfg.Backup.Schedule == "" {
		errs = append(errs, validateError{
			Field:   "backup.schedule",
			Message: "required when backup is enabled",
		})
	}
	if cfg.Backup.Enabled && cfg.Backup.RetainDays < 0 {
		errs = append(errs, validateError{
			Field:   "backup.retain_days",
			Message: "must not be negative (0 = keep all) when backup is enabled",
		})
	}
	if cfg.Backup.Timezone != "" {
		if _, err := time.LoadLocation(cfg.Backup.Timezone); err != nil {
			errs = append(errs, validateError{
				Field:   "backup.timezone",
				Message: fmt.Sprintf("unknown IANA timezone %q (e.g. \"Australia/Sydney\", \"UTC\")", cfg.Backup.Timezone),
			})
		}
	}

	// Logging
	switch cfg.Logging.Level {
	case "debug", "info", "warn", "error":
		// ok
	case "":
		errs = append(errs, validateError{
			Field:   "logging.level",
			Message: "must not be empty (use debug, info, warn, or error)",
		})
	default:
		errs = append(errs, validateError{
			Field:   "logging.level",
			Message: fmt.Sprintf("unknown level %q (use debug, info, warn, or error)", cfg.Logging.Level),
		})
	}

	// Admin
	if cfg.Admin.ListenAddr == "" {
		errs = append(errs, validateError{
			Field:   "admin.listen_addr",
			Message: "must not be empty",
		})
	}
	if cfg.Admin.SessionTTLHours <= 0 {
		errs = append(errs, validateError{
			Field:   "admin.session_ttl_hours",
			Message: "must be greater than 0",
		})
	}

	return errs
}

func validateSecrets(secrets *config.VectisSecrets) []validateError {
	var errs []validateError

	// Database
	if secrets.Database.Host == "" {
		errs = append(errs, validateError{Field: "database.host", Message: "must not be empty"})
	}
	if secrets.Database.Port <= 0 || secrets.Database.Port > 65535 {
		errs = append(errs, validateError{Field: "database.port", Message: "must be between 1 and 65535"})
	}
	if secrets.Database.Name == "" {
		errs = append(errs, validateError{Field: "database.name", Message: "must not be empty"})
	}
	if secrets.Database.APIUser == "" {
		errs = append(errs, validateError{Field: "database.api_user", Message: "must not be empty"})
	}
	if secrets.Database.APIPassword == "" {
		errs = append(errs, validateError{Field: "database.api_password", Message: "must not be empty"})
	}
	if secrets.Database.PostfixUser == "" {
		errs = append(errs, validateError{Field: "database.postfix_user", Message: "must not be empty"})
	}
	if secrets.Database.PostfixPassword == "" {
		errs = append(errs, validateError{Field: "database.postfix_password", Message: "must not be empty"})
	}
	if secrets.Database.DovecotUser == "" {
		errs = append(errs, validateError{Field: "database.dovecot_user", Message: "must not be empty"})
	}
	if secrets.Database.DovecotPassword == "" {
		errs = append(errs, validateError{Field: "database.dovecot_password", Message: "must not be empty"})
	}

	// Valkey
	if secrets.Valkey.Host == "" {
		errs = append(errs, validateError{Field: "valkey.host", Message: "must not be empty"})
	}
	if secrets.Valkey.Port <= 0 || secrets.Valkey.Port > 65535 {
		errs = append(errs, validateError{Field: "valkey.port", Message: "must be between 1 and 65535"})
	}
	if secrets.Valkey.Password == "" {
		errs = append(errs, validateError{Field: "valkey.password", Message: "must not be empty"})
	}

	// API
	if secrets.API.Secret == "" {
		errs = append(errs, validateError{Field: "api.secret", Message: "must not be empty"})
	} else if len(secrets.API.Secret) < 32 {
		errs = append(errs, validateError{Field: "api.secret", Message: "must be at least 32 characters long"})
	}
	if secrets.API.AdminEmail == "" {
		errs = append(errs, validateError{Field: "api.admin_email", Message: "must not be empty"})
	}
	if secrets.API.AdminPassword == "" {
		errs = append(errs, validateError{Field: "api.admin_password", Message: "must not be empty"})
	}

	// Orchestrator
	if secrets.Orchestrator.Token == "" {
		errs = append(errs, validateError{Field: "orchestrator.token", Message: "must not be empty"})
	}

	// DKIM
	if secrets.DKIM.KeyBasePath == "" {
		errs = append(errs, validateError{Field: "dkim.key_base_path", Message: "must not be empty"})
	}

	return errs
}

// ---------------------------------------------------------------------------
// config diff
// ---------------------------------------------------------------------------

// diffResult is the JSON-serialisable output of the diff command.
type diffResult struct {
	HasChanges bool                  `json:"has_changes"`
	Files      []engine.FileDiff     `json:"files"`
	Actions    []engine.ServiceAction `json:"actions"`
}

func runDiff(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	outputDir, _ := cmd.Flags().GetString("output-dir")

	cfg, secrets, err := loadConfigAndSecrets(cmd)
	if err != nil {
		return err
	}

	// Validate config.
	var valErrs []validateError
	valErrs = append(valErrs, validateConfig(cfg)...)
	valErrs = append(valErrs, validateSecrets(secrets)...)
	if len(valErrs) > 0 {
		if jsonOutput {
			result := validateResult{Valid: false, Errors: valErrs}
			out, _ := json.MarshalIndent(result, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Configuration has %d validation error(s):\n", len(valErrs))
			for _, e := range valErrs {
				fmt.Fprintf(cmd.ErrOrStderr(), "  - %s: %s\n", e.Field, e.Message)
			}
		}
		os.Exit(2)
		return nil
	}

	// Query domains from Postgres.
	domains, err := fetchDomains(cmd)
	if err != nil {
		return err
	}

	// Generate expected configs.
	data := engine.NewTemplateData(cfg, secrets, domains)
	data.SpamListEntries = fetchSpamListEntries(cmd)
	files, err := engine.Generate(data)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: template generation failed: %s\n", err)
		os.Exit(1)
		return nil
	}

	// Compare against disk.
	diffs, err := engine.DiffFiles(outputDir, files)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: diff failed: %s\n", err)
		os.Exit(1)
		return nil
	}

	// Determine service actions.
	actions := engine.DetermineActions(diffs)

	hasChanges := len(diffs) > 0

	if jsonOutput {
		result := diffResult{
			HasChanges: hasChanges,
			Files:      diffs,
			Actions:    actions,
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		if !hasChanges {
			fmt.Fprintln(cmd.OutOrStdout(), "No configuration changes pending.")
		} else {
			fmt.Fprintf(cmd.OutOrStdout(), "%d file(s) changed:\n", len(diffs))
			for _, d := range diffs {
				fmt.Fprintf(cmd.OutOrStdout(), "  [%s] %s\n", d.Status, d.RelPath)
			}
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Service actions required:")
			for _, a := range actions {
				if a.Action == "none" {
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  %s: %s", a.Service, a.Action)
				if a.Reason != "" {
					fmt.Fprintf(cmd.OutOrStdout(), " (due to: %s)", a.Reason)
				}
				fmt.Fprintln(cmd.OutOrStdout())
			}
		}
	}

	if hasChanges {
		os.Exit(1)
	}
	return nil
}

// ---------------------------------------------------------------------------
// config apply
// ---------------------------------------------------------------------------

// applyResult is the JSON-serialisable output of the apply command.
type applyResult struct {
	FilesWritten int                    `json:"files_written"`
	Diffs        []engine.FileDiff      `json:"diffs"`
	Actions      []engine.ServiceAction `json:"actions"`
	Results      []engine.ReloadResult  `json:"results,omitempty"`
	Success      bool                   `json:"success"`
}

func runApply(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	dryRun, _ := cmd.Flags().GetBool("dry-run")
	outputDir, _ := cmd.Flags().GetString("output-dir")

	// --dry-run is equivalent to diff.
	if dryRun {
		return runDiff(cmd, args)
	}

	cfg, secrets, err := loadConfigAndSecrets(cmd)
	if err != nil {
		return err
	}

	// Validate config.
	var valErrs []validateError
	valErrs = append(valErrs, validateConfig(cfg)...)
	valErrs = append(valErrs, validateSecrets(secrets)...)
	if len(valErrs) > 0 {
		if jsonOutput {
			result := validateResult{Valid: false, Errors: valErrs}
			out, _ := json.MarshalIndent(result, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
		} else {
			fmt.Fprintf(cmd.ErrOrStderr(), "Configuration has %d validation error(s):\n", len(valErrs))
			for _, e := range valErrs {
				fmt.Fprintf(cmd.ErrOrStderr(), "  - %s: %s\n", e.Field, e.Message)
			}
		}
		os.Exit(2)
		return nil
	}

	// Query domains from Postgres.
	domains, err := fetchDomains(cmd)
	if err != nil {
		return err
	}

	// Generate expected configs.
	data := engine.NewTemplateData(cfg, secrets, domains)
	data.SpamListEntries = fetchSpamListEntries(cmd)
	files, err := engine.Generate(data)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: template generation failed: %s\n", err)
		os.Exit(1)
		return nil
	}

	// Diff first to know what changed.
	diffs, err := engine.DiffFiles(outputDir, files)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: diff failed: %s\n", err)
		os.Exit(1)
		return nil
	}

	// Write files.
	if err := engine.WriteFiles(outputDir, files); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: write failed: %s\n", err)
		os.Exit(1)
		return nil
	}

	// Write Docker secret files.
	secretsDir := filepath.Join(outputDir, "secrets")
	if err := engine.WriteSecrets(secretsDir, data); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: write secrets failed: %s\n", err)
		os.Exit(1)
		return nil
	}

	// Determine and execute service actions.
	actions := engine.DetermineActions(diffs)
	results := engine.ExecuteActions(actions)

	// Check for partial failures.
	allSuccess := true
	for _, r := range results {
		if !r.Success {
			allSuccess = false
			break
		}
	}

	if jsonOutput {
		result := applyResult{
			FilesWritten: len(files),
			Diffs:        diffs,
			Actions:      actions,
			Results:      results,
			Success:      allSuccess,
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Wrote %d config file(s) to %s\n", len(files), outputDir)
		if len(diffs) > 0 {
			fmt.Fprintf(cmd.OutOrStdout(), "%d file(s) changed:\n", len(diffs))
			for _, d := range diffs {
				fmt.Fprintf(cmd.OutOrStdout(), "  [%s] %s\n", d.Status, d.RelPath)
			}
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "No files changed.")
		}

		if len(results) > 0 {
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Service actions:")
			for _, r := range results {
				status := "OK"
				if !r.Success {
					status = "FAILED"
				}
				fmt.Fprintf(cmd.OutOrStdout(), "  %s %s: %s\n", r.Service, r.Action, status)
				if r.Error != "" {
					fmt.Fprintf(cmd.OutOrStdout(), "    Error: %s\n", r.Error)
				}
			}
		}

		if allSuccess {
			fmt.Fprintln(cmd.OutOrStdout(), "\nConfiguration applied successfully.")
		} else {
			fmt.Fprintln(cmd.OutOrStdout(), "\nConfiguration applied with errors.")
		}
	}

	if !allSuccess {
		os.Exit(1)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// loadConfigAndSecrets loads both config.yaml and secrets.yaml from the --config-dir flag.
func loadConfigAndSecrets(cmd *cobra.Command) (*config.VectisConfig, *config.VectisSecrets, error) {
	configDir, err := cmd.Flags().GetString("config-dir")
	if err != nil {
		return nil, nil, err
	}

	cfg, secrets, err := config.LoadAll(configDir)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	return cfg, secrets, nil
}

// fetchDomains connects to the database and retrieves all domains.
func fetchDomains(cmd *cobra.Command) ([]repository.Domain, error) {
	pool, _, cleanup := connectDB(cmd)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	repo := repository.NewDomainRepo(pool)
	domains, err := repo.List(ctx, nil)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: failed to list domains: %s\n", err)
		os.Exit(1)
	}
	return domains, nil
}

// fetchSpamListEntries connects to the database and retrieves all per-domain
// allow/block entries for rspamd map generation. Best-effort: when the
// table does not yet exist (pre-migration 000016) the error is logged and
// an empty slice returned, so `vectis config diff/apply` still works on
// older schemas.
func fetchSpamListEntries(cmd *cobra.Command) []engine.SpamListInfo {
	pool, _, cleanup := connectDB(cmd)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	repo := repository.NewSpamListRepo(pool)
	entries, err := repo.ListAll(ctx)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Warning: failed to load spam list entries (advanced spam config will be empty): %s\n", err)
		return nil
	}
	out := make([]engine.SpamListInfo, 0, len(entries))
	for _, e := range entries {
		out = append(out, engine.SpamListInfo{
			DomainName: e.DomainName,
			Kind:       e.Kind,
			Scope:      e.Scope,
			Pattern:    e.Pattern,
		})
	}
	return out
}

func init() {
	// Diff flags.
	diffCmd.Flags().String("output-dir", defaultOutputDir, "Output directory for generated config files")
	diffCmd.Flags().String("db-host", "", "Override database host for connection (templates still use secrets.yaml value)")

	// Apply flags.
	applyCmd.Flags().String("output-dir", defaultOutputDir, "Output directory for generated config files")
	applyCmd.Flags().Bool("dry-run", false, "Show what would change without applying (equivalent to diff)")
	applyCmd.Flags().String("db-host", "", "Override database host for connection (templates still use secrets.yaml value)")

	configCmd.AddCommand(validateCmd)
	configCmd.AddCommand(diffCmd)
	configCmd.AddCommand(applyCmd)
	RootCmd.AddCommand(configCmd)
}
