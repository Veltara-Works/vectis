package cli

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/Veltara-Works/vectis/internal/secretcrypto"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

// `vectis mailbox import` queues an import of an external IMAP account INTO a
// Vectis mailbox (an imapsync-equivalent). The host CLI only writes a pending
// imap_import_jobs row — the API container's import worker picks it up (recovery
// scan) and runs it, authenticating to Dovecot via a short-lived auth token.
// See vectis-private #4. import-status / import-cancel inspect and stop a run.

var (
	importEmail        string
	importSourceHost   string
	importSourcePort   int
	importSourceUser   string
	importSourcePass   string
	importPassStdin    bool
	importNoTLS        bool
	importStatusEmail  string
	importStatusJob    string
	importCancelJob    string
)

var mailboxImportCmd = &cobra.Command{
	Use:   "import",
	Short: "Queue an import of an external IMAP account into a mailbox",
	RunE:  runMailboxImport,
}

var mailboxImportStatusCmd = &cobra.Command{
	Use:   "import-status",
	Short: "Show recent import jobs for a mailbox",
	RunE:  runMailboxImportStatus,
}

var mailboxImportCancelCmd = &cobra.Command{
	Use:   "import-cancel",
	Short: "Cancel a pending or running import job",
	RunE:  runMailboxImportCancel,
}

// importRepo builds an IMAPImportRepo with the same at-rest key the API worker
// uses, so the source password it encrypts can be decrypted on the import path.
func importRepo(pool *pgxpool.Pool, secret string) *repository.IMAPImportRepo {
	key := secretcrypto.DeriveKey([]byte(secret), "vectis-imap-import-v1")
	return repository.NewIMAPImportRepo(pool, key)
}

func runMailboxImport(cmd *cobra.Command, args []string) error {
	if importEmail == "" || importSourceHost == "" || importSourceUser == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --email, --source-host and --source-user are required")
		os.Exit(2)
	}

	pass := importSourcePass
	if importPassStdin {
		line, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
		if err != nil && line == "" {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: reading password from stdin: %s\n", err)
			os.Exit(1)
		}
		pass = strings.TrimRight(line, "\r\n")
	}
	if pass == "" {
		pass = os.Getenv("VECTIS_IMPORT_SOURCE_PASSWORD")
	}
	if pass == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: a source password is required (--source-password, --source-password-stdin, or VECTIS_IMPORT_SOURCE_PASSWORD)")
		os.Exit(2)
	}

	pool, secrets, cleanup := connectDB(cmd)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mbox := resolveMailboxByEmail(cmd, ctx, pool, importEmail)

	job, err := importRepo(pool, secrets.API.Secret).Create(ctx, repository.ImportCreate{
		MailboxID:      mbox.ID,
		SourceHost:     importSourceHost,
		SourcePort:     importSourcePort,
		SourceTLS:      !importNoTLS,
		SourceUser:     importSourceUser,
		SourcePassword: pass,
	})
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(cmd.OutOrStdout(),
		"Queued import job %s for %s (source %s@%s). The import worker will begin shortly;\n"+
			"track it with: vectis mailbox import-status --email %s\n",
		job.ID, importEmail, importSourceUser, importSourceHost, importEmail)
	return nil
}

func runMailboxImportStatus(cmd *cobra.Command, args []string) error {
	if importStatusEmail == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --email is required")
		os.Exit(2)
	}
	pool, secrets, cleanup := connectDB(cmd)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mbox := resolveMailboxByEmail(cmd, ctx, pool, importStatusEmail)
	repo := importRepo(pool, secrets.API.Secret)

	jobs, err := repo.ListByMailbox(ctx, mbox.ID, 20)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	if importStatusJob != "" {
		jobs = filterJob(jobs, importStatusJob)
	}
	if len(jobs) == 0 {
		fmt.Fprintf(cmd.OutOrStdout(), "No import jobs for %s.\n", importStatusEmail)
		return nil
	}

	tw := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "JOB ID\tSTATUS\tPROGRESS\tIMPORTED\tSKIPPED\tFOLDER\tSTARTED\tERROR")
	for _, j := range jobs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n",
			j.ID, j.Status, progressText(j), j.ImportedCount, j.SkippedCount,
			deref(j.CurrentFolder), j.StartedAt.Format("2006-01-02 15:04"), deref(j.ErrorMessage))
	}
	tw.Flush()
	return nil
}

func runMailboxImportCancel(cmd *cobra.Command, args []string) error {
	if importCancelJob == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --job is required")
		os.Exit(2)
	}
	pool, secrets, cleanup := connectDB(cmd)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cancelled, err := importRepo(pool, secrets.API.Secret).Cancel(ctx, importCancelJob)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	if !cancelled {
		fmt.Fprintf(cmd.ErrOrStderr(), "Job %s is not pending/running (already finished?); nothing to cancel.\n", importCancelJob)
		os.Exit(1)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Cancellation requested for import job %s; the worker stops at the next checkpoint.\n", importCancelJob)
	return nil
}

func filterJob(jobs []repository.ImportJob, id string) []repository.ImportJob {
	for _, j := range jobs {
		if j.ID == id {
			return []repository.ImportJob{j}
		}
	}
	return nil
}

func progressText(j repository.ImportJob) string {
	if j.Progress < 0 {
		return "—"
	}
	if j.TotalMessages > 0 {
		return fmt.Sprintf("%d%% (%d msgs)", j.Progress, j.TotalMessages)
	}
	return fmt.Sprintf("%d%%", j.Progress)
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func init() {
	mailboxImportCmd.Flags().StringVar(&importEmail, "email", "", "Target mailbox address (user@domain, required)")
	mailboxImportCmd.Flags().StringVar(&importSourceHost, "source-host", "", "Source IMAP host (required)")
	mailboxImportCmd.Flags().IntVar(&importSourcePort, "source-port", 0, "Source IMAP port (default 993, or 143 with --no-tls)")
	mailboxImportCmd.Flags().StringVar(&importSourceUser, "source-user", "", "Source IMAP username (required)")
	mailboxImportCmd.Flags().StringVar(&importSourcePass, "source-password", "", "Source IMAP password (prefer --source-password-stdin or VECTIS_IMPORT_SOURCE_PASSWORD)")
	mailboxImportCmd.Flags().BoolVar(&importPassStdin, "source-password-stdin", false, "Read the source password from stdin")
	mailboxImportCmd.Flags().BoolVar(&importNoTLS, "no-tls", false, "Connect with plaintext + STARTTLS (port 143) instead of implicit TLS")

	mailboxImportStatusCmd.Flags().StringVar(&importStatusEmail, "email", "", "Mailbox address (user@domain, required)")
	mailboxImportStatusCmd.Flags().StringVar(&importStatusJob, "job", "", "Show only this job id")

	mailboxImportCancelCmd.Flags().StringVar(&importCancelJob, "job", "", "Import job id to cancel (required)")

	mailboxCmd.AddCommand(mailboxImportCmd)
	mailboxCmd.AddCommand(mailboxImportStatusCmd)
	mailboxCmd.AddCommand(mailboxImportCancelCmd)
}
