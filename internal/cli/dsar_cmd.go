package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/dsar"
	"github.com/Veltara-Works/vectis/internal/logging"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// The DSAR CLI is intended to run INSIDE the api container, e.g.
//
//	docker exec vectis-api vectis dsar export --subject alice@example.com --output /tmp/alice.zip
//
// Only there can it both resolve the Docker-internal "postgres" host and read
// the mail-data volume the export streams message bodies from. (Run on the bare
// host it will fail to connect to the DB, the same constraint backup works
// around with docker exec.)
//
// Unlike the HTTP routes, the CLI does NOT consult the ValidonX `dsar`
// entitlement. That gate guards the remote API surface; the CLI is operator
// break-glass tooling that already requires shell access to the box, which by
// itself grants full Postgres + Maildir access (the operator could run the
// equivalent SQL/`rm` by hand — see the manual path in operator-dsar-runbook).
// This matches the other operator CLIs (e.g. `vectis saml init-sp`), which are
// likewise unlicensed. The entitlement is enforced where it's a real boundary.

var dsarCmd = &cobra.Command{
	Use:   "dsar",
	Short: "GDPR data-subject access + erasure (Enterprise)",
	Long: "Data-subject access (Art.15 export) and erasure (Art.17) for a single mail subject.\n\n" +
		"Run inside the api container so the database host resolves and the mail volume is mounted:\n" +
		"  docker exec vectis-api vectis dsar export --subject user@example.com --output /tmp/user.zip",
}

var (
	dsarSubject string
	dsarOutput  string
	dsarConfirm bool
)

var dsarExportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export a subject's access package (Art.15) to a zip",
	RunE:  runDSARExport,
}

var dsarEraseCmd = &cobra.Command{
	Use:   "erase",
	Short: "Erase a subject's live personal data (Art.17). Irreversible — requires --confirm",
	RunE:  runDSARErase,
}

var dsarListCmd = &cobra.Command{
	Use:   "erasures",
	Short: "List recorded erasure tombstones (the suppression list)",
	RunE:  runDSARList,
}

// dsarBuild loads config + secrets, opens a pool, and returns a ready DSAR
// service plus a cleanup func. The pool path is the in-container one (resolves
// "postgres"); there is no docker-exec fallback because the export also needs
// the mail volume, which only exists inside the container.
func dsarBuild(cmd *cobra.Command) (*dsar.Service, context.Context, context.CancelFunc, func(), error) {
	configDir, _ := cmd.Flags().GetString("config-dir")
	cfg, secrets, err := config.LoadAll(configDir)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	logger := logging.NewLogger("warn")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)

	pool, err := openPool(ctx, secrets, "", logger)
	if err != nil {
		cancel()
		return nil, nil, nil, nil, fmt.Errorf("connect to database: %w", err)
	}

	svc := dsar.NewService(
		repository.NewDomainRepo(pool), repository.NewMailboxRepo(pool),
		repository.NewAliasRepo(pool), repository.NewAdminRepo(pool),
		repository.NewMessageRepo(pool), repository.NewAuditRepo(pool),
		repository.NewErasureTombstoneRepo(pool),
		dsar.MailRootFromLocation(cfg.Dovecot.MailLocation), logger,
	)
	cleanup := func() { pool.Close() }
	return svc, ctx, cancel, cleanup, nil
}

func runDSARExport(cmd *cobra.Command, args []string) error {
	if dsarSubject == "" {
		return errors.New("--subject is required")
	}
	if dsarOutput == "" {
		return errors.New("--output (zip path) is required")
	}

	svc, ctx, cancel, cleanup, err := dsarBuild(cmd)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	defer cancel()
	defer cleanup()

	f, err := os.Create(dsarOutput)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: cannot create %s: %s\n", dsarOutput, err)
		os.Exit(1)
	}
	defer f.Close()

	sum, err := svc.Export(ctx, dsarSubject, nil, f)
	if err != nil {
		if errors.Is(err, dsar.ErrSubjectNotFound) {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: no mailbox found for %q\n", dsarSubject)
			os.Exit(1)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: export failed: %s\n", err)
		os.Exit(1)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		out, _ := json.MarshalIndent(map[string]any{"output": dsarOutput, "summary": sum}, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Exported %s: %d messages, %d mail files, %d aliases → %s\n",
			dsarSubject, sum.Messages, sum.MailFiles, sum.Aliases, dsarOutput)
	}
	return nil
}

func runDSARErase(cmd *cobra.Command, args []string) error {
	if dsarSubject == "" {
		return errors.New("--subject is required")
	}
	if !dsarConfirm {
		fmt.Fprintln(cmd.ErrOrStderr(), "Error: erasure is irreversible. Re-run with --confirm to proceed.")
		os.Exit(2)
	}

	svc, ctx, cancel, cleanup, err := dsarBuild(cmd)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	defer cancel()
	defer cleanup()

	// CLI runs as an operator on the box, not an authenticated admin, so the
	// audit actor is nil (a system action) — never a sentinel string, which
	// would fail the audit_log.admin_id UUID FK.
	res, err := svc.Erase(ctx, dsarSubject, nil)
	if err != nil {
		if errors.Is(err, dsar.ErrSubjectNotFound) {
			fmt.Fprintf(cmd.ErrOrStderr(), "Error: no mailbox found for %q\n", dsarSubject)
			os.Exit(1)
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: erase failed: %s\n", err)
		os.Exit(1)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
	} else {
		fmt.Fprintf(cmd.OutOrStdout(),
			"Erased %s: %d message rows, %d aliases, mailbox=%t, maildir=%t (tombstone %s)\n",
			res.SubjectEmail, res.MessageMetadata, res.Aliases, res.MailboxDeleted, res.MaildirRemoved, res.TombstoneID)
		if res.AdminRetained {
			fmt.Fprintf(cmd.OutOrStdout(),
				"Note: an operator/admin account shares this address and was left in place — review and remove it manually if required.\n")
		}
	}
	return nil
}

func runDSARList(cmd *cobra.Command, args []string) error {
	svc, ctx, cancel, cleanup, err := dsarBuild(cmd)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}
	defer cancel()
	defer cleanup()

	tombs, err := svc.ListErasures(ctx)
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), "Error: %s\n", err)
		os.Exit(1)
	}

	jsonOutput, _ := cmd.Flags().GetBool("json")
	if jsonOutput {
		if tombs == nil {
			tombs = []repository.ErasureTombstone{}
		}
		out, _ := json.MarshalIndent(tombs, "", "  ")
		fmt.Fprintln(cmd.OutOrStdout(), string(out))
		return nil
	}

	if len(tombs) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), "No erasures recorded.")
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "%-40s %-20s %s\n", "Subject", "Erased", "Reconcile runs")
	for _, t := range tombs {
		fmt.Fprintf(cmd.OutOrStdout(), "%-40s %-20s %d\n",
			t.SubjectEmail, t.ErasedAt.Format("2006-01-02 15:04:05"), t.ReconcileRuns)
	}
	return nil
}

func init() {
	dsarExportCmd.Flags().StringVar(&dsarSubject, "subject", "", "Subject email address (required)")
	dsarExportCmd.Flags().StringVar(&dsarOutput, "output", "", "Path to write the export zip (required)")

	dsarEraseCmd.Flags().StringVar(&dsarSubject, "subject", "", "Subject email address (required)")
	dsarEraseCmd.Flags().BoolVar(&dsarConfirm, "confirm", false, "Confirm irreversible erasure")

	dsarCmd.AddCommand(dsarExportCmd)
	dsarCmd.AddCommand(dsarEraseCmd)
	dsarCmd.AddCommand(dsarListCmd)
	RootCmd.AddCommand(dsarCmd)
}
