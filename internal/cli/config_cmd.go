package cli

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/spf13/cobra"
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
	if cfg.Backup.Enabled && cfg.Backup.RetainDays <= 0 {
		errs = append(errs, validateError{
			Field:   "backup.retain_days",
			Message: "must be greater than 0 when backup is enabled",
		})
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

func init() {
	configCmd.AddCommand(validateCmd)
	RootCmd.AddCommand(configCmd)
}
