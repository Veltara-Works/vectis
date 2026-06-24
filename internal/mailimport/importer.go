package mailimport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

const (
	// destHost/destPort are the local Dovecot the importer writes into. It is our
	// own service on a private network behind a shared cert, so TLS verification
	// is skipped (matches the rest of the internal IMAP wiring).
	destHost = "vectis-dovecot"
	destPort = 993

	// importPurpose tags minted auth tokens; tokenTTL is deliberately generous —
	// importing a multi-GB account can run for a long time and the token must
	// outlive the whole run (it is revoked promptly when the run ends).
	importPurpose = "import"
	tokenTTL      = 12 * time.Hour

	// destSeparator is Dovecot's namespace hierarchy separator (dovecot.conf
	// `separator = /`). Source folder delimiters are normalised to this.
	destSeparator = "/"

	// progressEvery throttles DB progress writes and cancellation polls to one per
	// this many processed messages (plus once per folder boundary).
	progressEvery = 50

	// maxMsgAttempts bounds per-message fetch+append retries. Real-world IMAP
	// imports hit transient blips (dropped connections, server hiccups); a small
	// retry rides them out. A message still failing after this aborts the job
	// with context — and because the import dedupes by Message-ID, a re-run
	// resumes from where it stopped rather than re-copying everything.
	maxMsgAttempts = 3
)

// msgRetryBackoff is the pause between per-message retries. A var (not const) so
// tests can zero it.
var msgRetryBackoff = 2 * time.Second

// errCancelled is an internal sentinel: the job was cancelled mid-run. The runner
// already set status=cancelled, so the engine just stops without Fail/Complete.
var errCancelled = errors.New("import cancelled")

// JobStore is the subset of repository.IMAPImportRepo the engine needs. An
// interface keeps the engine unit-testable without a database.
type JobStore interface {
	GetByID(ctx context.Context, jobID string) (*repository.ImportJob, error)
	DecryptPassword(ctx context.Context, jobID string) (string, error)
	TargetEmail(ctx context.Context, mailboxID string) (string, error)
	SetRunning(ctx context.Context, jobID string, totalMessages int) error
	UpdateProgress(ctx context.Context, jobID string, progress int, currentFolder string, imported, skipped int) error
	Complete(ctx context.Context, jobID string, imported, skipped int) error
	Fail(ctx context.Context, jobID, errMsg string) error
	Status(ctx context.Context, jobID string) (string, error)
}

// TokenMinter mints and revokes the short-lived Dovecot auth token the importer
// authenticates with (repository.DovecotAuthTokenRepo).
type TokenMinter interface {
	Mint(ctx context.Context, targetUser, purpose string, ttl time.Duration) (*repository.MintedToken, error)
	Revoke(ctx context.Context, id string) error
}

// sourceConn / destConn abstract the IMAP wrappers so tests can substitute fakes.
// *SourceClient and *DestClient satisfy them.
type sourceConn interface {
	Folders() ([]Folder, error)
	SelectFolder(name string) (uint32, error)
	Overviews(count uint32) ([]Overview, error)
	FetchBody(uid uint32) ([]byte, error)
	Close()
}

type destConn interface {
	EnsureFolder(name string) error
	ExistingMessageIDs(folder string) (map[string]struct{}, error)
	Append(folder string, body []byte, flags []string, date time.Time) error
	Close()
}

// Importer runs a single import job end to end.
type Importer struct {
	store  JobStore
	tokens TokenMinter
	logger *slog.Logger

	// Dialers are fields so tests can inject fakes; they default to the real
	// IMAP wrappers in NewImporter.
	dialSource func(SourceConfig) (sourceConn, error)
	dialDest   func(DestConfig) (destConn, error)
}

// NewImporter builds an importer wired to the real IMAP dialers.
func NewImporter(store JobStore, tokens TokenMinter, logger *slog.Logger) *Importer {
	return &Importer{
		store:  store,
		tokens: tokens,
		logger: logger,
		dialSource: func(c SourceConfig) (sourceConn, error) {
			return Dial(c)
		},
		dialDest: func(c DestConfig) (destConn, error) {
			return DialDest(c)
		},
	}
}

// Run executes one import job. It never returns an error to the caller — every
// outcome (success, failure, cancellation) is recorded on the job row — so the
// worker can fire-and-forget. A panic-free, self-contained unit of work.
func (im *Importer) Run(ctx context.Context, jobID string) {
	log := im.logger.With("job_id", jobID)

	job, err := im.store.GetByID(ctx, jobID)
	if err != nil {
		log.Error("import: load job failed", "error", err)
		return
	}
	if job.Status != "pending" && job.Status != "running" {
		log.Info("import: job not runnable, skipping", "status", job.Status)
		return
	}

	if err := im.run(ctx, log, job); err != nil {
		if errors.Is(err, errCancelled) {
			log.Info("import: cancelled")
			return
		}
		log.Error("import: failed", "error", err)
		if ferr := im.store.Fail(ctx, jobID, err.Error()); ferr != nil {
			log.Error("import: recording failure failed", "error", ferr)
		}
	}
}

// run is the worker body; a returned error (other than errCancelled) is recorded
// as the job's failure by Run.
func (im *Importer) run(ctx context.Context, log *slog.Logger, job *repository.ImportJob) error {
	// Resolve the destination login and credentials.
	email, err := im.store.TargetEmail(ctx, job.MailboxID)
	if err != nil {
		return fmt.Errorf("resolve target mailbox: %w", err)
	}
	srcPass, err := im.store.DecryptPassword(ctx, job.ID)
	if err != nil {
		return fmt.Errorf("decrypt source credentials: %w", err)
	}

	// Mint a short-lived auth token so we can log into Dovecot AS the target
	// mailbox, and always revoke it when the run ends.
	token, err := im.tokens.Mint(ctx, email, importPurpose, tokenTTL)
	if err != nil {
		return fmt.Errorf("mint dovecot auth token: %w", err)
	}
	defer func() {
		if rerr := im.tokens.Revoke(context.WithoutCancel(ctx), token.ID); rerr != nil {
			log.Error("import: revoke auth token failed", "error", rerr, "token_id", token.ID)
		}
	}()

	// Connect to both ends.
	src, err := im.dialSource(SourceConfig{
		Host: job.SourceHost, Port: job.SourcePort, TLS: job.SourceTLS,
		User: job.SourceUser, Pass: srcPass,
	})
	if err != nil {
		return fmt.Errorf("connect to source: %w", err)
	}
	defer src.Close()

	dst, err := im.dialDest(DestConfig{
		Host: destHost, Port: destPort, User: email, Pass: token.Password, TLSInsecure: true,
	})
	if err != nil {
		return fmt.Errorf("connect to destination: %w", err)
	}
	defer dst.Close()

	// Enumerate selectable source folders, INBOX first.
	folders, err := im.selectableFolders(src)
	if err != nil {
		return err
	}

	// Pre-count for a meaningful progress percentage.
	total := 0
	for _, f := range folders {
		n, err := src.SelectFolder(f.Name)
		if err != nil {
			return fmt.Errorf("select source folder %q: %w", f.Name, err)
		}
		total += int(n)
	}
	if err := im.store.SetRunning(ctx, job.ID, total); err != nil {
		return fmt.Errorf("mark job running: %w", err)
	}
	log.Info("import: starting", "target", email, "folders", len(folders), "total_messages", total)

	processed, imported, skipped := 0, 0, 0
	for _, f := range folders {
		if err := im.checkCancelled(ctx, job.ID); err != nil {
			return err
		}
		destFolder := MapFolder(f, destSeparator)
		if err := dst.EnsureFolder(destFolder); err != nil {
			return fmt.Errorf("ensure dest folder %q: %w", destFolder, err)
		}
		existing, err := dst.ExistingMessageIDs(destFolder)
		if err != nil {
			return fmt.Errorf("scan existing messages in %q: %w", destFolder, err)
		}

		count, err := src.SelectFolder(f.Name)
		if err != nil {
			return fmt.Errorf("select source folder %q: %w", f.Name, err)
		}
		overviews, err := src.Overviews(count)
		if err != nil {
			return fmt.Errorf("read overview of %q: %w", f.Name, err)
		}

		for _, ov := range overviews {
			// Idempotent re-runs: skip a message already present at the dest
			// (matched by normalized Message-ID). Messages with no Message-ID
			// can't be de-duplicated and are always copied.
			if ov.MessageID != "" {
				if _, dup := existing[ov.MessageID]; dup {
					skipped++
					processed++
					continue
				}
			}

			if err := im.copyMessage(src, dst, destFolder, ov); err != nil {
				return fmt.Errorf("import message uid %d (message-id %q) in %q after %d attempts: %w",
					ov.UID, ov.MessageID, f.Name, maxMsgAttempts, err)
			}
			if ov.MessageID != "" {
				existing[ov.MessageID] = struct{}{} // guard against dupes within this run
			}
			imported++
			processed++

			if processed%progressEvery == 0 {
				if err := im.checkCancelled(ctx, job.ID); err != nil {
					return err
				}
				im.reportProgress(ctx, log, job.ID, processed, total, destFolder, imported, skipped)
			}
		}
		im.reportProgress(ctx, log, job.ID, processed, total, destFolder, imported, skipped)
	}

	if err := im.store.Complete(ctx, job.ID, imported, skipped); err != nil {
		return fmt.Errorf("mark job complete: %w", err)
	}
	log.Info("import: completed", "imported", imported, "skipped", skipped)
	return nil
}

// selectableFolders lists source folders, drops \Noselect containers, and orders
// INBOX first so the most important mail lands before progress is far along.
func (im *Importer) selectableFolders(src sourceConn) ([]Folder, error) {
	all, err := src.Folders()
	if err != nil {
		return nil, fmt.Errorf("list source folders: %w", err)
	}
	var out []Folder
	for _, f := range all {
		// Skip container-only folders and Gmail's virtual labels (All Mail /
		// Important / Starred) whose messages duplicate the real folders.
		if f.IsNoSelect() || f.IsDuplicativeVirtual() {
			continue
		}
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := strings.EqualFold(out[i].Name, "INBOX"), strings.EqualFold(out[j].Name, "INBOX")
		if ai != aj {
			return ai // INBOX sorts first
		}
		return false
	})
	return out, nil
}

// checkCancelled returns errCancelled if the job has been cancelled (or no longer
// runnable). Read errors are logged but don't abort the import.
func (im *Importer) checkCancelled(ctx context.Context, jobID string) error {
	status, err := im.store.Status(ctx, jobID)
	if err != nil {
		im.logger.Warn("import: cancellation check failed", "job_id", jobID, "error", err)
		return nil
	}
	if status == "cancelled" {
		return errCancelled
	}
	return nil
}

// reportProgress writes a progress update, logging (but not failing) on error —
// progress is advisory and must never abort a working import.
func (im *Importer) reportProgress(ctx context.Context, log *slog.Logger, jobID string, processed, total int, folder string, imported, skipped int) {
	pct := percent(processed, total)
	if err := im.store.UpdateProgress(ctx, jobID, pct, folder, imported, skipped); err != nil {
		log.Warn("import: progress update failed", "error", err)
	}
}

// percent computes processed/total as 0-100, capped, with -1 for an unknown total.
func percent(processed, total int) int {
	if total <= 0 {
		return -1
	}
	p := processed * 100 / total
	if p > 100 {
		p = 100
	}
	return p
}

// copyMessage fetches one message and appends it to the destination, retrying a
// few times to ride out transient IMAP errors. Fetch and append are retried as a
// unit (a re-fetch on append failure is harmless — the message isn't recorded as
// present until the whole op succeeds).
func (im *Importer) copyMessage(src sourceConn, dst destConn, destFolder string, ov Overview) error {
	var err error
	for attempt := 1; attempt <= maxMsgAttempts; attempt++ {
		var body []byte
		if body, err = src.FetchBody(ov.UID); err == nil {
			err = dst.Append(destFolder, body, sanitizeFlags(ov.Flags), ov.InternalDate)
		}
		if err == nil {
			return nil
		}
		im.logger.Warn("import: message copy failed, retrying",
			"uid", ov.UID, "attempt", attempt, "max", maxMsgAttempts, "error", err)
		if attempt < maxMsgAttempts {
			time.Sleep(msgRetryBackoff)
		}
	}
	return err
}

// sanitizeFlags drops flags that cannot be set via APPEND. \Recent is
// server-managed and rejected if supplied; everything else (system flags and
// keywords) is preserved.
func sanitizeFlags(flags []string) []string {
	out := make([]string, 0, len(flags))
	for _, f := range flags {
		if strings.EqualFold(f, "\\Recent") {
			continue
		}
		out = append(out, f)
	}
	return out
}
