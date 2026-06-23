package cli

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

// `vectis mailbox suspend-send` / `resume-send` toggle the per-mailbox
// send_suspended flag from the host CLI. Suspension was previously API-only;
// these wrap the same AbuseRepo the admin API uses. Enforcement on the
// submission path (587/465) is handled by the policy server (internal/policy),
// so a suspended mailbox can still receive but cannot send via SMTP-AUTH or the
// HTTP API. See vectis-private #5.

var (
	mailboxSuspendEmail  string
	mailboxSuspendReason string
	mailboxResumeEmail   string
)

var mailboxSuspendSendCmd = &cobra.Command{
	Use:   "suspend-send",
	Short: "Suspend a mailbox from sending (receive-only); inbound delivery is unaffected",
	RunE:  runMailboxSuspendSend,
}

var mailboxResumeSendCmd = &cobra.Command{
	Use:   "resume-send",
	Short: "Re-enable sending for a previously suspended mailbox",
	RunE:  runMailboxResumeSend,
}

// resolveMailboxByEmail looks up a mailbox by its user@domain address, exiting
// with a clear message on any failure.
func resolveMailboxByEmail(cmd *cobra.Command, ctx context.Context, pool *pgxpool.Pool, email string) *repository.Mailbox {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --email must be in user@domain format")
		os.Exit(2)
	}
	domain, err := repository.NewDomainRepo(pool).GetByName(ctx, parts[1])
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	if domain == nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: domain %s not found\n", parts[1])
		os.Exit(1)
	}
	mbox, err := repository.NewMailboxRepo(pool).GetByEmail(ctx, domain.ID, parts[0])
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	if mbox == nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: mailbox %s not found\n", email)
		os.Exit(1)
	}
	return mbox
}

func runMailboxSuspendSend(cmd *cobra.Command, args []string) error {
	if mailboxSuspendEmail == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --email is required")
		os.Exit(2)
	}
	reason := mailboxSuspendReason
	if reason == "" {
		reason = "Suspended by operator (CLI)"
	}

	pool, _, cleanup := connectDB(cmd)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mbox := resolveMailboxByEmail(cmd, ctx, pool, mailboxSuspendEmail)
	abuse := repository.NewAbuseRepo(pool)
	if err := abuse.SuspendMailbox(ctx, mbox.ID, reason); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	action := "suspend"
	abuse.LogEvent(ctx, &mbox.DomainID, &mbox.ID, "manual_suspend", "info",
		map[string]string{"reason": reason, "source": "cli"}, &action)

	fmt.Fprintf(cmd.OutOrStdout(), "Mailbox %s suspended from sending (receive-only). Reason: %s\n",
		mailboxSuspendEmail, reason)
	return nil
}

func runMailboxResumeSend(cmd *cobra.Command, args []string) error {
	if mailboxResumeEmail == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --email is required")
		os.Exit(2)
	}

	pool, _, cleanup := connectDB(cmd)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mbox := resolveMailboxByEmail(cmd, ctx, pool, mailboxResumeEmail)
	abuse := repository.NewAbuseRepo(pool)
	if err := abuse.UnsuspendMailbox(ctx, mbox.ID); err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	action := "none"
	abuse.LogEvent(ctx, &mbox.DomainID, &mbox.ID, "unsuspend", "info",
		map[string]string{"source": "cli"}, &action)

	fmt.Fprintf(cmd.OutOrStdout(), "Mailbox %s sending re-enabled.\n", mailboxResumeEmail)
	return nil
}

func init() {
	mailboxSuspendSendCmd.Flags().StringVar(&mailboxSuspendEmail, "email", "", "Mailbox address (user@domain, required)")
	mailboxSuspendSendCmd.Flags().StringVar(&mailboxSuspendReason, "reason", "", "Reason recorded in the abuse log")
	mailboxResumeSendCmd.Flags().StringVar(&mailboxResumeEmail, "email", "", "Mailbox address (user@domain, required)")

	mailboxCmd.AddCommand(mailboxSuspendSendCmd)
	mailboxCmd.AddCommand(mailboxResumeSendCmd)
}
