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

var (
	mailboxEmail       string
	mailboxPassword    string
	mailboxQuota       int
	mailboxDisplayName string
)

func runMailboxAdd(cmd *cobra.Command, args []string) error {
	if mailboxEmail == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --email is required")
		os.Exit(2)
	}
	if mailboxPassword == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --password is required")
		os.Exit(2)
	}

	parts := strings.SplitN(mailboxEmail, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --email must be in user@domain format")
		os.Exit(2)
	}
	localPart := parts[0]
	domainNameStr := parts[1]

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

func init() {
	mailboxAddCmd.Flags().StringVar(&mailboxEmail, "email", "", "Email address (user@domain, required)")
	mailboxAddCmd.Flags().StringVar(&mailboxPassword, "password", "", "Mailbox password (required)")
	mailboxAddCmd.Flags().IntVar(&mailboxQuota, "quota", 0, "Quota in MB (default: 1024)")
	mailboxAddCmd.Flags().StringVar(&mailboxDisplayName, "display-name", "", "Display name")

	mailboxCmd.AddCommand(mailboxAddCmd)
	RootCmd.AddCommand(mailboxCmd)
}
