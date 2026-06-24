package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/secretcrypto"
	"github.com/Veltara-Works/vectis/internal/types"
)

// ImportJob is a row in imap_import_jobs (status-safe — never carries the source
// password). Mirrors the backup_jobs job model.
type ImportJob struct {
	ID            string     `json:"id"`
	MailboxID     string     `json:"mailbox_id"`
	SourceHost    string     `json:"source_host"`
	SourcePort    int        `json:"source_port"`
	SourceTLS     bool       `json:"source_tls"`
	SourceUser    string     `json:"source_user"`
	Status        string     `json:"status"` // pending|running|completed|failed|cancelled
	Progress      int        `json:"progress"`
	TotalMessages int        `json:"total_messages"`
	ImportedCount int        `json:"imported_count"`
	SkippedCount  int        `json:"skipped_count"`
	CurrentFolder *string    `json:"current_folder,omitempty"`
	ErrorMessage  *string    `json:"error_message,omitempty"`
	StartedAt     time.Time  `json:"started_at"`
	CompletedAt   *time.Time `json:"completed_at,omitempty"`
	TriggeredBy   *string    `json:"triggered_by,omitempty"`
}

// ImportCreate holds the fields for a new import job. SourcePassword is
// plaintext here and encrypted before it touches the database.
type ImportCreate struct {
	MailboxID      string
	SourceHost     string
	SourcePort     int
	SourceTLS      bool
	SourceUser     string
	SourcePassword string
	TriggeredBy    *string
}

// importJobColumns is the status-safe projection — deliberately excludes
// source_password so a status read can never leak the credential.
const importJobColumns = `id, mailbox_id, source_host, source_port, source_tls, source_user,
	status, progress, total_messages, imported_count, skipped_count, current_folder,
	error_message, started_at, completed_at, triggered_by`

// IMAPImportRepo handles imap_import_jobs CRUD. encKey encrypts source_password
// at rest (secretcrypto), mirroring WebhookRepo.
type IMAPImportRepo struct {
	db     *pgxpool.Pool
	encKey []byte
}

// NewIMAPImportRepo creates the repo. encKey should be derived once via
// secretcrypto.DeriveKey(masterSecret, "vectis-imap-import-v1").
func NewIMAPImportRepo(db *pgxpool.Pool, encKey []byte) *IMAPImportRepo {
	return &IMAPImportRepo{db: db, encKey: encKey}
}

// Create inserts a new pending import job, encrypting the source password.
func (r *IMAPImportRepo) Create(ctx context.Context, in ImportCreate) (*ImportJob, error) {
	encPw, err := secretcrypto.Encrypt(r.encKey, in.SourcePassword)
	if err != nil {
		return nil, fmt.Errorf("encrypt source password: %w", err)
	}
	if in.SourcePort == 0 {
		in.SourcePort = 993
	}

	job := &ImportJob{
		ID:          types.NewUUIDv7(),
		MailboxID:   in.MailboxID,
		SourceHost:  in.SourceHost,
		SourcePort:  in.SourcePort,
		SourceTLS:   in.SourceTLS,
		SourceUser:  in.SourceUser,
		Status:      "pending",
		StartedAt:   time.Now().UTC(),
		TriggeredBy: in.TriggeredBy,
	}

	_, err = r.db.Exec(ctx,
		`INSERT INTO imap_import_jobs
		   (id, mailbox_id, source_host, source_port, source_tls, source_user, source_password,
		    status, progress, started_at, triggered_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, 'pending', 0, $8, $9)`,
		job.ID, job.MailboxID, job.SourceHost, job.SourcePort, job.SourceTLS, job.SourceUser,
		encPw, job.StartedAt, job.TriggeredBy,
	)
	if err != nil {
		return nil, fmt.Errorf("insert import job: %w", err)
	}
	return job, nil
}

// TargetEmail resolves a mailbox id to its full email (local_part@domain) — the
// Dovecot login the importer authenticates AS and the auth-token target_user.
// Returns an empty string if the mailbox no longer exists.
func (r *IMAPImportRepo) TargetEmail(ctx context.Context, mailboxID string) (string, error) {
	var email string
	err := r.db.QueryRow(ctx,
		`SELECT CONCAT(m.local_part, '@', d.name)
		   FROM mailboxes m JOIN domains d ON m.domain_id = d.id
		  WHERE m.id = $1`, mailboxID).Scan(&email)
	if err != nil {
		return "", fmt.Errorf("resolve target email for mailbox %s: %w", mailboxID, err)
	}
	return email, nil
}

// DecryptPassword returns the decrypted source password for the runner. Kept
// separate from the status reads so the credential is only ever materialised on
// the import path.
func (r *IMAPImportRepo) DecryptPassword(ctx context.Context, jobID string) (string, error) {
	var enc string
	if err := r.db.QueryRow(ctx,
		`SELECT source_password FROM imap_import_jobs WHERE id = $1`, jobID,
	).Scan(&enc); err != nil {
		return "", fmt.Errorf("get import job password: %w", err)
	}
	pw, err := secretcrypto.Decrypt(r.encKey, enc)
	if err != nil {
		return "", fmt.Errorf("decrypt source password: %w", err)
	}
	return pw, nil
}

func scanImportJob(row interface{ Scan(...any) error }, j *ImportJob) error {
	return row.Scan(&j.ID, &j.MailboxID, &j.SourceHost, &j.SourcePort, &j.SourceTLS, &j.SourceUser,
		&j.Status, &j.Progress, &j.TotalMessages, &j.ImportedCount, &j.SkippedCount, &j.CurrentFolder,
		&j.ErrorMessage, &j.StartedAt, &j.CompletedAt, &j.TriggeredBy)
}

// GetByID returns a job (without the password).
func (r *IMAPImportRepo) GetByID(ctx context.Context, jobID string) (*ImportJob, error) {
	var j ImportJob
	err := scanImportJob(r.db.QueryRow(ctx,
		`SELECT `+importJobColumns+` FROM imap_import_jobs WHERE id = $1`, jobID), &j)
	if err != nil {
		return nil, fmt.Errorf("get import job: %w", err)
	}
	return &j, nil
}

// ListByMailbox returns recent jobs for a mailbox, newest first.
func (r *IMAPImportRepo) ListByMailbox(ctx context.Context, mailboxID string, limit int) ([]ImportJob, error) {
	if limit <= 0 {
		limit = 20
	}
	rows, err := r.db.Query(ctx,
		`SELECT `+importJobColumns+` FROM imap_import_jobs
		 WHERE mailbox_id = $1 ORDER BY started_at DESC LIMIT $2`, mailboxID, limit)
	if err != nil {
		return nil, fmt.Errorf("list import jobs: %w", err)
	}
	defer rows.Close()
	return collectImportJobs(rows)
}

// ListActive returns pending/running jobs (for worker pickup + startup recovery).
func (r *IMAPImportRepo) ListActive(ctx context.Context) ([]ImportJob, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+importJobColumns+` FROM imap_import_jobs
		 WHERE status IN ('pending','running') ORDER BY started_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list active import jobs: %w", err)
	}
	defer rows.Close()
	return collectImportJobs(rows)
}

func collectImportJobs(rows interface {
	Next() bool
	Scan(...any) error
	Err() error
}) ([]ImportJob, error) {
	var jobs []ImportJob
	for rows.Next() {
		var j ImportJob
		if err := scanImportJob(rows, &j); err != nil {
			return nil, fmt.Errorf("scan import job: %w", err)
		}
		jobs = append(jobs, j)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate import jobs: %w", err)
	}
	return jobs, nil
}

// SetRunning marks a job running and records the discovered message total.
func (r *IMAPImportRepo) SetRunning(ctx context.Context, jobID string, totalMessages int) error {
	_, err := r.db.Exec(ctx,
		`UPDATE imap_import_jobs SET status = 'running', total_messages = $1 WHERE id = $2`,
		totalMessages, jobID)
	if err != nil {
		return fmt.Errorf("set import job running: %w", err)
	}
	return nil
}

// UpdateProgress records incremental progress during a run.
func (r *IMAPImportRepo) UpdateProgress(ctx context.Context, jobID string, progress int, currentFolder string, imported, skipped int) error {
	_, err := r.db.Exec(ctx,
		`UPDATE imap_import_jobs
		   SET progress = $1, current_folder = $2, imported_count = $3, skipped_count = $4
		 WHERE id = $5`,
		progress, currentFolder, imported, skipped, jobID)
	if err != nil {
		return fmt.Errorf("update import job progress: %w", err)
	}
	return nil
}

// Complete marks a job completed with final counts.
func (r *IMAPImportRepo) Complete(ctx context.Context, jobID string, imported, skipped int) error {
	_, err := r.db.Exec(ctx,
		`UPDATE imap_import_jobs
		   SET status = 'completed', progress = 100, imported_count = $1, skipped_count = $2,
		       current_folder = NULL, completed_at = $3
		 WHERE id = $4`,
		imported, skipped, time.Now().UTC(), jobID)
	if err != nil {
		return fmt.Errorf("complete import job: %w", err)
	}
	return nil
}

// Fail marks a job failed with an error message.
func (r *IMAPImportRepo) Fail(ctx context.Context, jobID, errMsg string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE imap_import_jobs SET status = 'failed', error_message = $1, completed_at = $2
		 WHERE id = $3`,
		truncate(errMsg, 2000), time.Now().UTC(), jobID)
	if err != nil {
		return fmt.Errorf("fail import job: %w", err)
	}
	return nil
}

// Cancel requests cancellation; the runner observes the status and stops.
func (r *IMAPImportRepo) Cancel(ctx context.Context, jobID string) (bool, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE imap_import_jobs SET status = 'cancelled', completed_at = $1
		 WHERE id = $2 AND status IN ('pending','running')`,
		time.Now().UTC(), jobID)
	if err != nil {
		return false, fmt.Errorf("cancel import job: %w", err)
	}
	return tag.RowsAffected() > 0, nil
}

// Status returns just the current status (cheap; used by the runner to observe
// cancellation between folders/messages).
func (r *IMAPImportRepo) Status(ctx context.Context, jobID string) (string, error) {
	var status string
	if err := r.db.QueryRow(ctx,
		`SELECT status FROM imap_import_jobs WHERE id = $1`, jobID).Scan(&status); err != nil {
		return "", fmt.Errorf("get import job status: %w", err)
	}
	return status, nil
}
