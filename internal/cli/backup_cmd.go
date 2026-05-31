package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/backup"
	"github.com/Veltara-Works/vectis/internal/logging"
)

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup and restore commands",
}

var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a full backup",
	Long: "Creates a full backup of the database, mail data, configuration, and DKIM keys.\n\n" +
		"By default the database is dumped via `docker exec` into the vectis-postgres\n" +
		"container. Use --db-host to dump over TCP from a directly-reachable Postgres\n" +
		"instead (requires pg_dump on the host).",
	RunE: runBackupCreate,
}

var backupRestoreCmd = &cobra.Command{
	Use:   "restore <path>",
	Short: "Restore from a backup archive",
	Long:  "Restores database, mail data, config, and DKIM keys from a backup archive. Requires --confirm flag.",
	Args:  cobra.ExactArgs(1),
	RunE:  runBackupRestore,
}

var backupListCmd = &cobra.Command{
	Use:   "list",
	Short: "List available backups",
	RunE:  runBackupList,
}

var (
	backupOutput  string
	backupConfirm bool
	backupDBHost  string
)

func runBackupCreate(cmd *cobra.Command, args []string) error {
	// Create runs as a host CLI operation. By default the host cannot resolve the
	// Docker-internal "postgres" hostname and may not have pg_dump installed, so
	// the Manager dumps the DB via `docker exec` as the superuser (nil pool, no
	// DB-backed job tracking). --db-host overrides this for operators whose
	// Postgres is directly reachable: it dumps over TCP as the app user instead.
	// The in-app/API scheduler keeps using the pool path. (Finding B follow-up —
	// the create-side twin of the restore fix; see
	// docs/notes/dr-drill-scenario-b-2026-05-30.md.)
	secrets, err := loadSecrets(cmd)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	quiet := isQuiet(cmd)
	jsonOutput, _ := cmd.Flags().GetBool("json")

	logLevel := "info"
	if quiet {
		logLevel = "error"
	}
	logger := logging.NewLogger(logLevel)

	cfg := backup.DefaultConfig()
	cfg.DBName = secrets.Database.Name
	if backupDBHost != "" {
		// Operator opted into a directly-reachable Postgres: dump over TCP as the
		// app user from this host, instead of docker exec into the container.
		// Requires pg_dump on the host and network reach to the DB.
		cfg.DirectDB = true
		cfg.DBHost = backupDBHost
		cfg.DBPort = secrets.Database.Port
		cfg.DBUser = secrets.Database.APIUser
		cfg.DBPassword = secrets.Database.APIPassword
	} else {
		// Default host path: dump via docker exec as the superuser.
		cfg.SuperuserPassword = secrets.Database.SuperuserPassword
	}
	if secrets.DKIM.KeyBasePath != "" {
		cfg.DKIMDir = secrets.DKIM.KeyBasePath
	}
	if secrets.API.BackupEncryptionKey != "" {
		cfg.EncryptionKey = secrets.API.BackupEncryptionKey
	} else if secrets.API.Secret != "" {
		cfg.EncryptionKey = secrets.API.Secret
	}

	mgr := backup.NewManager(nil, logger, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	if !quiet {
		fmt.Fprintln(cmd.OutOrStdout(), "Creating backup...")
	}

	path, size, err := mgr.Create(ctx, nil)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: backup failed: %s\n", err)
		os.Exit(1)
	}

	// If --output is specified, move the backup file.
	if backupOutput != "" {
		if err := os.Rename(path, backupOutput); err != nil {
			// Rename may fail across filesystems; fall back to copy.
			if cpErr := copyBackupFile(path, backupOutput); cpErr != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "Error: failed to move backup to %s: %s\n", backupOutput, cpErr)
				os.Exit(1)
			}
			os.Remove(path)
		}
		path = backupOutput
		info, _ := os.Stat(path)
		if info != nil {
			size = info.Size()
		}
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(map[string]any{
			"path": path,
			"size": size,
		}, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else if !quiet {
		fmt.Fprintf(cmd.OutOrStdout(), "\nBackup saved: %s (%s)\n", path, formatBytes(size))
	}

	return nil
}

func runBackupRestore(cmd *cobra.Command, args []string) error {
	backupPath := args[0]

	if !backupConfirm {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: restore is a destructive operation. Use --confirm to proceed.")
		os.Exit(2)
	}

	// Verify the file exists.
	if _, err := os.Stat(backupPath); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: backup file not found: %s\n", backupPath)
		os.Exit(1)
	}

	// Restore runs WITHOUT a DB pool. On a real install the host cannot resolve
	// the Docker-internal "postgres" hostname (and during restore the DB has
	// just been stopped), so the Manager drives the DB via `docker exec` as the
	// superuser and skips DB-backed job tracking. (Finding B, 2026-05-30
	// Scenario-B DR drill — see docs/notes/dr-drill-scenario-b-2026-05-30.md.)
	secrets, err := loadSecrets(cmd)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	quiet := isQuiet(cmd)
	jsonOutput, _ := cmd.Flags().GetBool("json")

	logLevel := "info"
	if quiet {
		logLevel = "error"
	}
	logger := logging.NewLogger(logLevel)

	cfg := backup.DefaultConfig()
	cfg.DBName = secrets.Database.Name
	cfg.SuperuserPassword = secrets.Database.SuperuserPassword
	if secrets.DKIM.KeyBasePath != "" {
		cfg.DKIMDir = secrets.DKIM.KeyBasePath
	}
	if secrets.API.BackupEncryptionKey != "" {
		cfg.EncryptionKey = secrets.API.BackupEncryptionKey
	} else if secrets.API.Secret != "" {
		cfg.EncryptionKey = secrets.API.Secret
	}

	mgr := backup.NewManager(nil, logger, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Minute)
	defer cancel()

	if !quiet {
		fmt.Fprintf(cmd.OutOrStdout(), "Restoring from %s...\n", backupPath)
	}

	if err := mgr.Restore(ctx, backupPath, nil); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: restore failed: %s\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(map[string]any{
			"status":      "completed",
			"backup_path": backupPath,
		}, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else if !quiet {
		fmt.Fprintln(cmd.OutOrStdout(), "\nRestore complete. All services restarted.")
	}

	return nil
}

func runBackupList(cmd *cobra.Command, args []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")

	// For listing backups on disk, we don't need a DB connection.
	// But we can also show job history from the DB if available.
	cfg := backup.DefaultConfig()

	logger := logging.NewLogger("warn")
	mgr := backup.NewManager(nil, logger, cfg)

	backups, err := mgr.List()
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		if backups == nil {
			backups = []backup.BackupInfo{}
		}
		out, _ := json.MarshalIndent(backups, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}

	if len(backups) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No backups found.")
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%-45s %-12s %s\n", "Name", "Size", "Created")
	fmt.Fprintln(cmd.OutOrStdout(), "─────────────────────────────────────────────────────────────────────")
	for _, b := range backups {
		fmt.Fprintf(cmd.OutOrStdout(), "%-45s %-12s %s\n",
			b.Name,
			formatBytes(b.Size),
			b.CreatedAt.Format("2006-01-02 15:04:05"),
		)
	}

	return nil
}

// formatBytes formats a byte count into a human-readable string.
func formatBytes(b int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case b >= GB:
		return fmt.Sprintf("%.1f GB", float64(b)/float64(GB))
	case b >= MB:
		return fmt.Sprintf("%.1f MB", float64(b)/float64(MB))
	case b >= KB:
		return fmt.Sprintf("%.1f KB", float64(b)/float64(KB))
	default:
		return fmt.Sprintf("%d B", b)
	}
}

// copyBackupFile copies a file from src to dst (used when os.Rename fails
// across filesystem boundaries).
func copyBackupFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := out.ReadFrom(in); err != nil {
		return err
	}
	return out.Close()
}

func init() {
	backupCreateCmd.Flags().StringVar(&backupOutput, "output", "", "Output path for the backup archive")
	backupCreateCmd.Flags().StringVar(&backupDBHost, "db-host", "", "Dump the DB over TCP from this directly-reachable Postgres host (requires pg_dump on the host) instead of docker exec into the vectis-postgres container")
	backupRestoreCmd.Flags().BoolVar(&backupConfirm, "confirm", false, "Confirm destructive restore operation")

	backupCmd.AddCommand(backupCreateCmd)
	backupCmd.AddCommand(backupRestoreCmd)
	backupCmd.AddCommand(backupListCmd)
	RootCmd.AddCommand(backupCmd)
}
