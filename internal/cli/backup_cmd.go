package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/backup"
	"github.com/Veltara-Works/vectis/internal/logging"
)

// apiContainerName is the container that mounts both the mail-data volume and
// can reach Postgres over the Docker network — the only place a FULL backup
// (including mail) can run.
const apiContainerName = "vectis-api"

var backupCmd = &cobra.Command{
	Use:   "backup",
	Short: "Backup and restore commands",
}

var backupCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a backup (full when the stack is up; database/config/DKIM otherwise)",
	Long: "Creates a backup of the database, mailboxes, configuration, and DKIM keys.\n\n" +
		"By default, when the vectis-api container is running, this delegates to it via\n" +
		"`docker exec` for a FULL backup — the api container mounts the mail-data volume\n" +
		"and reaches Postgres over the Docker network, so the archive includes mail. The\n" +
		"file is written to /var/vectis/backups (bind-mounted from the host, so it shows\n" +
		"up in `vectis backup list`).\n\n" +
		"When the stack is down (a DR situation), it falls back to a host-local backup of\n" +
		"the database (dumped via `docker exec` into vectis-postgres as the superuser),\n" +
		"config, and DKIM keys — but NOT mail, which lives in a Docker volume the host\n" +
		"cannot read; it warns when it produces such a partial archive.\n\n" +
		"Use --db-host to force a host-side DB dump over TCP from a directly-reachable\n" +
		"Postgres (requires pg_dump on the host); this is always a host-local, partial\n" +
		"(no-mail) archive.",
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
	quiet := isQuiet(cmd)
	jsonOutput, _ := cmd.Flags().GetBool("json")

	// Prefer a FULL backup. A host-run backup can only archive what lives on the
	// host filesystem; the maildirs live in the `mail-data` Docker volume,
	// mounted only INSIDE the containers, so a host-side run silently drops mail
	// — the half-right-is-wrong footgun. The full-coverage backup runs inside the
	// api container (it has the mail volume AND reaches Postgres over the Docker
	// network). When the operator hasn't explicitly opted into the host-side
	// direct-DB path (--db-host) and the api container is up, delegate to it via
	// `docker exec`. The archive lands in /var/vectis/backups, which the api
	// service bind-mounts from the host, so the file is visible on the host (and
	// to `vectis backup list`) afterwards. Only fall back to the host-local
	// config/DB/DKIM path when the stack is down — the DR case, where a host-side
	// capture is exactly what's wanted, and which warns it is partial. If
	// delegation is attempted but FAILS, surface the error rather than silently
	// producing a partial archive.
	if backupDBHost == "" && apiContainerRunning() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()

		if !quiet {
			fmt.Fprintln(cmd.OutOrStdout(), "Creating full backup (via the vectis-api container)...")
		}

		res, err := delegateContainerBackup(ctx)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: full backup failed: %s\n", err)
			os.Exit(1)
		}

		path, size := res.Path, res.Size
		// Honour --output on the host: the archive lives under /var/vectis/backups
		// (bind-mounted at the same path on the host), so it is reachable here.
		if backupOutput != "" {
			if err := os.Rename(path, backupOutput); err != nil {
				if cpErr := copyBackupFile(path, backupOutput); cpErr != nil {
					fmt.Fprintf(cmd.ErrOrStderr(), "Error: failed to move backup to %s: %s\n", backupOutput, cpErr)
					os.Exit(1)
				}
				os.Remove(path)
			}
			path = backupOutput
			if info, _ := os.Stat(path); info != nil {
				size = info.Size()
			}
		}

		if jsonOutput {
			out, _ := json.MarshalIndent(map[string]any{
				"path":          path,
				"size":          size,
				"mail_included": res.MailIncluded,
			}, "", "  ")
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
		} else if !quiet {
			fmt.Fprintf(cmd.OutOrStdout(), "\nBackup saved: %s (%s)\n", path, formatBytes(size))
			if !res.MailIncluded {
				fmt.Fprintln(cmd.OutOrStdout(), "Note: no mail captured — the mail-data volume is empty (no mailboxes have received mail yet).")
			}
		}
		return nil
	}

	// Host-local path: reached when the operator chose --db-host (a deliberate
	// host-side DB dump) or the stack is down. By default the host cannot resolve
	// the Docker-internal "postgres" hostname and may not have pg_dump installed,
	// so the Manager dumps the DB via `docker exec` as the superuser (nil pool, no
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

	// A host-run backup can only archive what lives on the host filesystem. The
	// maildirs live in the `mail-data` Docker volume, mounted only INSIDE the
	// containers at cfg.MailDataDir — so a host backup captures no mail, the
	// half-right-is-wrong footgun that bites during a restore. The full-coverage
	// backup runs inside the api container (the scheduler, or
	// POST /api/v1/backup/create), where the volume is mounted and the DB is
	// dumped over TCP.
	//
	// Detection is by CONTENT, not mere existence: `vectis install` does
	// `mkdir -p /var/vectis/mail` on the host (install.sh), and the named volume
	// then shadows that dir inside the containers — so on a standard install the
	// host path EXISTS but is an empty shadow. os.Stat would give a false
	// "included"; we instead treat "no entries" (absent OR empty) as "no mail
	// captured". A non-Docker install with real mail on the host has entries and
	// correctly does not warn.
	mailIncluded := false
	if entries, readErr := os.ReadDir(cfg.MailDataDir); readErr == nil && len(entries) > 0 {
		mailIncluded = true
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
		result := map[string]any{
			"path":          path,
			"size":          size,
			"mail_included": mailIncluded,
		}
		if !mailIncluded {
			result["warning"] = "maildirs not included — a host-run backup cannot access the mail-data volume; use the in-app scheduler or POST /api/v1/backup/create for a full backup"
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else if !quiet {
		fmt.Fprintf(cmd.OutOrStdout(), "\nBackup saved: %s (%s)\n", path, formatBytes(size))
	}

	// Always surface the partial-backup warning (even under --quiet): an operator
	// must never mistake a host-run config/DB-only archive for a full backup.
	if !mailIncluded {
		fmt.Fprintf(cmd.ErrOrStderr(),
			"\nWARNING: PARTIAL backup — no mailboxes captured.\n"+
				"  %s holds no mail on the host: it is the mail-data Docker volume, mounted\n"+
				"  only inside the containers (the host path is absent or an empty shadow), so\n"+
				"  this archive holds the database, config and DKIM keys but no mail. For a FULL\n"+
				"  backup use the in-app scheduler or POST /api/v1/backup/create, which run\n"+
				"  inside the api container.\n",
			cfg.MailDataDir)
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

// apiContainerRunning reports whether the vectis-api container is up. A FULL
// backup (including mail) can only run inside that container.
func apiContainerRunning() bool {
	out, err := exec.Command("docker", "inspect", "-f", "{{.State.Running}}", apiContainerName).Output()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// containerBackupArgs builds the `docker exec` argv that triggers a full backup
// inside the api container. --db-host postgres forces the TCP dump path (the
// in-container CLI has no docker socket of its own to exec into Postgres);
// --json --quiet keep stdout to pure JSON we can parse.
func containerBackupArgs() []string {
	return []string{"exec", apiContainerName, "vectis", "backup", "create", "--db-host", "postgres", "--json", "--quiet"}
}

// containerBackupResult mirrors the JSON emitted by `vectis backup create --json`.
type containerBackupResult struct {
	Path         string `json:"path"`
	Size         int64  `json:"size"`
	MailIncluded bool   `json:"mail_included"`
}

// delegateContainerBackup triggers a FULL backup inside the vectis-api
// container via `docker exec`. The api container has both the mail-data volume
// and the database (over the Docker network), so unlike a host-run backup it
// captures mail. The archive is written to /var/vectis/backups, which the api
// service bind-mounts from the host, so the file is visible on the host
// afterwards.
func delegateContainerBackup(ctx context.Context) (*containerBackupResult, error) {
	cmd := exec.CommandContext(ctx, "docker", containerBackupArgs()...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("in-container backup failed: %w: %s", err, strings.TrimSpace(stderr.String()))
	}
	var res containerBackupResult
	if err := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &res); err != nil {
		return nil, fmt.Errorf("parsing in-container backup output: %w (got: %q)", err, strings.TrimSpace(stdout.String()))
	}
	if res.Path == "" {
		return nil, fmt.Errorf("in-container backup returned no path (output: %q)", strings.TrimSpace(stdout.String()))
	}
	return &res, nil
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
