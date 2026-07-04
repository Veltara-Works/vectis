package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/auth"
	"github.com/Veltara-Works/vectis/internal/repository"
	"github.com/spf13/cobra"
)

var mailboxCmd = &cobra.Command{
	Use:   "mailbox",
	Short: "Mailbox management commands",
}

var mailboxAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new mailbox",
	RunE:  runMailboxAdd,
}

var mailboxListCmd = &cobra.Command{
	Use:   "list",
	Short: "List mailboxes (all domains, or a single domain with --domain)",
	RunE:  runMailboxList,
}

var mailboxRemoveCmd = &cobra.Command{
	Use:   "remove",
	Short: "Remove a mailbox by email address",
	Long: "Remove a mailbox by --email. Deletes the mailbox metadata row; the " +
		"on-disk maildir is Dovecot-owned and left untouched. Destructive — requires --confirm.",
	RunE: runMailboxRemove,
}

var (
	mailboxEmail         string
	mailboxPassword      string
	mailboxQuota         int
	mailboxDisplayName   string
	mailboxListDomain    string
	mailboxRemoveEmail   string
	mailboxRemoveConfirm bool
)

// mailboxRow is the display/JSON projection of a mailbox for `mailbox list`.
// It composes the full address from local_part + domain name (the repository
// Mailbox row carries only local_part and a domain_id).
type mailboxRow struct {
	Email         string    `json:"email"`
	QuotaMB       int       `json:"quota_mb"`
	Active        bool      `json:"active"`
	SendSuspended bool      `json:"send_suspended"`
	CreatedAt     time.Time `json:"created_at"`
}

// mailboxRowsForDomain projects a domain's mailboxes into display rows,
// composing local_part@domain into the full address.
func mailboxRowsForDomain(domainName string, mboxes []repository.Mailbox) []mailboxRow {
	rows := make([]mailboxRow, 0, len(mboxes))
	for _, m := range mboxes {
		rows = append(rows, mailboxRow{
			Email:         m.LocalPart + "@" + domainName,
			QuotaMB:       m.QuotaMB,
			Active:        m.Active,
			SendSuspended: m.SendSuspended,
			CreatedAt:     m.CreatedAt,
		})
	}
	return rows
}

func runMailboxAdd(cmd *cobra.Command, args []string) error {
	if mailboxEmail == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --email is required")
		os.Exit(2)
	}
	if mailboxPassword == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --password is required")
		os.Exit(2)
	}

	localPart, domainNameStr, ok := splitEmailAddress(mailboxEmail)
	if !ok {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --email must be in user@domain format")
		os.Exit(2)
	}

	pool, _, cleanup := connectDB(cmd)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	jsonOutput, _ := cmd.Flags().GetBool("json")

	// Find domain.
	domainRepo := repository.NewDomainRepo(pool)
	domain, err := domainRepo.GetByName(ctx, domainNameStr)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	if domain == nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: domain %s not found. Create it first: vectis domain add --name %s\n",
			domainNameStr, domainNameStr)
		os.Exit(1)
	}
	if !domain.Active {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: domain %s is not active\n", domainNameStr)
		os.Exit(1)
	}

	// Check uniqueness.
	mboxRepo := repository.NewMailboxRepo(pool)
	existing, _ := mboxRepo.GetByEmail(ctx, domain.ID, localPart)
	if existing != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: mailbox %s already exists\n", mailboxEmail)
		os.Exit(1)
	}

	// Hash password.
	hash, err := auth.HashPassword(mailboxPassword)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error hashing password: %s\n", err)
		os.Exit(1)
	}

	input := repository.MailboxCreate{
		DomainID:     domain.ID,
		LocalPart:    localPart,
		PasswordHash: hash,
	}
	if mailboxDisplayName != "" {
		input.DisplayName = &mailboxDisplayName
	}
	if mailboxQuota > 0 {
		input.QuotaMB = &mailboxQuota
	}

	mailbox, err := mboxRepo.Create(ctx, input)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(mailbox, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Mailbox %s created.\n", mailboxEmail)
		fmt.Fprintf(cmd.OutOrStdout(), "  Quota: %d MB\n", mailbox.QuotaMB)
		if mailbox.DisplayName != nil {
			fmt.Fprintf(cmd.OutOrStdout(), "  Name:  %s\n", *mailbox.DisplayName)
		}
	}
	return nil
}

func runMailboxList(cmd *cobra.Command, args []string) error {
	pool, _, cleanup := connectDB(cmd)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	jsonOutput, _ := cmd.Flags().GetBool("json")

	domainRepo := repository.NewDomainRepo(pool)
	mboxRepo := repository.NewMailboxRepo(pool)

	// Resolve the set of domains to enumerate: one when --domain is given,
	// otherwise all of them (ordered by name, matching `domain list`).
	var domains []repository.Domain
	if mailboxListDomain != "" {
		d, err := domainRepo.GetByName(ctx, mailboxListDomain)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
			os.Exit(1)
		}
		if d == nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: domain %s not found\n", mailboxListDomain)
			os.Exit(1)
		}
		domains = []repository.Domain{*d}
	} else {
		list, err := domainRepo.List(ctx, nil)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
			os.Exit(1)
		}
		domains = list
	}

	rows := []mailboxRow{}
	for _, d := range domains {
		mboxes, err := mboxRepo.ListByDomain(ctx, d.ID)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
			os.Exit(1)
		}
		rows = append(rows, mailboxRowsForDomain(d.Name, mboxes)...)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(rows, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}

	if len(rows) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No mailboxes found.")
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%-34s %-9s %-8s %-11s %s\n",
		"Email", "Quota", "Active", "Sending", "Created")
	fmt.Fprintln(cmd.OutOrStdout(), "──────────────────────────────────────────────────────────────────────────────")
	for _, r := range rows {
		active := "yes"
		if !r.Active {
			active = "no"
		}
		sending := "ok"
		if r.SendSuspended {
			sending = "suspended"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%-34s %-9s %-8s %-11s %s\n",
			r.Email, fmt.Sprintf("%d MB", r.QuotaMB), active, sending, r.CreatedAt.Format("2006-01-02"))
	}
	return nil
}

// splitEmailAddress splits user@domain into its parts, reporting ok=false for
// anything that is not exactly one non-empty local part and one non-empty
// domain.
func splitEmailAddress(email string) (local, domain string, ok bool) {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", false
	}
	return parts[0], parts[1], true
}

func runMailboxRemove(cmd *cobra.Command, args []string) error {
	if mailboxRemoveEmail == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --email is required")
		os.Exit(2)
	}
	localPart, domainNameStr, ok := splitEmailAddress(mailboxRemoveEmail)
	if !ok {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --email must be in user@domain format")
		os.Exit(2)
	}

	pool, _, cleanup := connectDB(cmd)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	jsonOutput, _ := cmd.Flags().GetBool("json")

	domainRepo := repository.NewDomainRepo(pool)
	domain, err := domainRepo.GetByName(ctx, domainNameStr)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	if domain == nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: domain %s not found\n", domainNameStr)
		os.Exit(1)
	}

	mboxRepo := repository.NewMailboxRepo(pool)
	mailbox, err := mboxRepo.GetByEmail(ctx, domain.ID, localPart)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	if mailbox == nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: mailbox %s not found\n", mailboxRemoveEmail)
		os.Exit(1)
	}

	if !mailboxRemoveConfirm {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: removing a mailbox is destructive. Re-run with --confirm to proceed.")
		os.Exit(1)
	}

	deleted, err := mboxRepo.Delete(ctx, mailbox.ID)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	if !deleted {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: mailbox %s not found\n", mailboxRemoveEmail)
		os.Exit(1)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(map[string]string{
			"message": "Mailbox removed",
			"mailbox": mailboxRemoveEmail,
		}, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Mailbox %s removed.\n", mailboxRemoveEmail)
	}
	return nil
}

func init() {
	mailboxAddCmd.Flags().StringVar(&mailboxEmail, "email", "", "Email address (user@domain, required)")
	mailboxAddCmd.Flags().StringVar(&mailboxPassword, "password", "", "Mailbox password (required)")
	mailboxAddCmd.Flags().IntVar(&mailboxQuota, "quota", 0, "Quota in MB (default: 1024)")
	mailboxAddCmd.Flags().StringVar(&mailboxDisplayName, "display-name", "", "Display name")
	mailboxListCmd.Flags().StringVar(&mailboxListDomain, "domain", "", "Only list mailboxes for this domain (default: all domains)")
	mailboxRemoveCmd.Flags().StringVar(&mailboxRemoveEmail, "email", "", "Email address to remove (user@domain, required)")
	mailboxRemoveCmd.Flags().BoolVar(&mailboxRemoveConfirm, "confirm", false, "Confirm destructive removal")

	mailboxCmd.AddCommand(mailboxAddCmd)
	mailboxCmd.AddCommand(mailboxListCmd)
	mailboxCmd.AddCommand(mailboxRemoveCmd)
	RootCmd.AddCommand(mailboxCmd)
}
