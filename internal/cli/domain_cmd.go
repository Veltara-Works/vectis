package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/dkim"
	"github.com/Veltara-Works/vectis/internal/logging"
	"github.com/Veltara-Works/vectis/internal/repository"
)

var domainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Domain management commands",
}

var domainAddCmd = &cobra.Command{
	Use:   "add",
	Short: "Add a new domain",
	RunE:  runDomainAdd,
}

var domainListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all domains",
	RunE:  runDomainList,
}

var (
	domainName      string
	domainSpamThres float64
	domainMaxMbox   int
	domainNoDKIM    bool
	domainActiveOnly bool
)

func runDomainAdd(cmd *cobra.Command, args []string) error {
	if domainName == "" {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: --name is required")
		os.Exit(2)
	}

	pool, secrets, cleanup := connectDB(cmd)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	jsonOutput, _ := cmd.Flags().GetBool("json")

	repo := repository.NewDomainRepo(pool)

	// Check uniqueness.
	existing, _ := repo.GetByName(ctx, domainName)
	if existing != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: domain %s already exists\n", domainName)
		os.Exit(1)
	}

	// Create domain.
	input := repository.DomainCreate{Name: domainName}
	if domainSpamThres > 0 {
		input.SpamThreshold = &domainSpamThres
	}
	if domainMaxMbox > 0 {
		input.MaxMailboxes = &domainMaxMbox
	}

	domain, err := repo.Create(ctx, input)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	// Generate DKIM keys unless --no-dkim.
	var kp *dkim.KeyPair
	if !domainNoDKIM && secrets.DKIM.KeyBasePath != "" {
		selector := dkim.DefaultSelector()
		kp, err = dkim.GenerateKey(secrets.DKIM.KeyBasePath, domainName, selector)
		if err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: DKIM key generation failed: %s\n", err)
		} else {
			keyPath := kp.KeyPath
			repo.Update(ctx, domain.ID, repository.DomainUpdate{
				DKIMSelector: &selector,
				DKIMKeyPath:  &keyPath,
			})
			domain, _ = repo.GetByID(ctx, domain.ID)
		}
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(domain, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Domain %s created.\n", domainName)

		if kp != nil {
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Add this DNS TXT record for DKIM:")
			fmt.Fprintf(cmd.OutOrStdout(), "  Name:  %s\n", kp.DNSName())
			fmt.Fprintf(cmd.OutOrStdout(), "  Value: %s\n", kp.DNSRecord())
			fmt.Fprintln(cmd.OutOrStdout())
			fmt.Fprintln(cmd.OutOrStdout(), "Also ensure these DNS records exist:")
			fmt.Fprintf(cmd.OutOrStdout(), "  SPF:   %s\n", dkim.SPFRecord(""))
			fmt.Fprintf(cmd.OutOrStdout(), "  DMARC: %s\n", dkim.DMARCRecord(domainName))
		}
	}
	return nil
}

func runDomainList(cmd *cobra.Command, args []string) error {
	pool, _, cleanup := connectDB(cmd)
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	jsonOutput, _ := cmd.Flags().GetBool("json")

	repo := repository.NewDomainRepo(pool)
	var activeFilter *bool
	if domainActiveOnly {
		t := true
		activeFilter = &t
	}

	domains, err := repo.List(ctx, activeFilter)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	if jsonOutput {
		out, _ := json.MarshalIndent(domains, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}

	if len(domains) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No domains found.")
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), "%-30s %-8s %-8s %-14s %s\n",
		"Name", "Active", "DKIM", "Selector", "Created")
	fmt.Fprintln(cmd.OutOrStdout(), "────────────────────────────────────────────────────────────────────────")
	for _, d := range domains {
		dkimStatus := "no"
		if d.DKIMKeyPath != nil && *d.DKIMKeyPath != "" {
			dkimStatus = "yes"
		}
		active := "yes"
		if !d.Active {
			active = "no"
		}
		fmt.Fprintf(cmd.OutOrStdout(), "%-30s %-8s %-8s %-14s %s\n",
			d.Name, active, dkimStatus, d.DKIMSelector, d.CreatedAt.Format("2006-01-02"))
	}
	return nil
}

// connectDB creates a DB pool from secrets.yaml and returns it with a cleanup function.
// If the calling command defines a --db-host flag and the caller passes a non-empty
// value, that value overrides secrets.Database.Host for the connection (useful when
// running the CLI from the host but Postgres is reachable via a Docker bridge IP).
// Commands that don't define the flag get the no-op default.
func connectDB(cmd *cobra.Command) (*pgxpool.Pool, *config.VectisSecrets, func()) {
	secrets, err := loadSecrets(cmd)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	logger := logging.NewLogger("warn")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	dbHost := secrets.Database.Host
	if override, _ := cmd.Flags().GetString("db-host"); override != "" {
		dbHost = override
	}
	dbCfg := database.ConfigFromSecrets(
		dbHost, secrets.Database.Port, secrets.Database.Name,
		secrets.Database.APIUser, secrets.Database.APIPassword,
	)
	pool, err := database.NewPool(ctx, dbCfg, logger)
	cancel()
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: database connection failed: %s\n", err)
		os.Exit(1)
	}

	return pool, secrets, func() { pool.Close() }
}

func init() {
	domainAddCmd.Flags().StringVar(&domainName, "name", "", "Domain name (required)")
	domainAddCmd.Flags().Float64Var(&domainSpamThres, "spam-threshold", 0, "Per-domain spam threshold")
	domainAddCmd.Flags().IntVar(&domainMaxMbox, "max-mailboxes", 0, "Maximum number of mailboxes")
	domainAddCmd.Flags().BoolVar(&domainNoDKIM, "no-dkim", false, "Skip DKIM key generation")
	domainListCmd.Flags().BoolVar(&domainActiveOnly, "active-only", false, "Show only active domains")

	domainCmd.AddCommand(domainAddCmd)
	domainCmd.AddCommand(domainListCmd)
	RootCmd.AddCommand(domainCmd)
}
