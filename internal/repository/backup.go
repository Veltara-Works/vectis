package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// BackupJob represents a row in the backup_jobs table.
type BackupJob struct {
	ID           string     `json:"id"`
	Action       string     `json:"action"` // "create" or "restore"
	Status       string     `json:"status"` // "pending", "running", "completed", "failed"
	BackupPath   *string    `json:"backup_path,omitempty"`
	Progress     int        `json:"progress"` // 0-100
	CurrentStep  *string    `json:"current_step,omitempty"`
	ErrorMessage *string    `json:"error_message,omitempty"`
	StartedAt    time.Time  `json:"started_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
	TriggeredBy  *string    `json:"triggered_by,omitempty"`
}

// BackupRepo handles backup_jobs CRUD operations.
type BackupRepo struct {
	db *pgxpool.Pool
}

// NewBackupRepo creates a new backup repository.
func NewBackupRepo(db *pgxpool.Pool) *BackupRepo {
	return &BackupRepo{db: db}
}

// Create inserts a new backup job and returns it.
func (r *BackupRepo) Create(ctx context.Context, action string, triggeredBy *string) (*BackupJob, error) {
	job := &BackupJob{
		ID:          types.NewUUIDv7(),
		Action:      action,
		Status:      "pending",
		Progress:    0,
		StartedAt:   time.Now().UTC(),
		TriggeredBy: triggeredBy,
	}

	_, err := r.db.Exec(ctx,
		`INSERT INTO backup_jobs (id, action, status, progress, started_at, triggered_by)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		job.ID, job.Action, job.Status, job.Progress, job.StartedAt, job.TriggeredBy,
	)
	if err != nil {
		return nil, fmt.Errorf("insert backup job: %w", err)
	}

	return job, nil
}

// UpdateProgress updates the progress and current step of a backup job.
func (r *BackupRepo) UpdateProgress(ctx context.Context, jobID string, progress int, currentStep string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE backup_jobs SET progress = $1, current_step = $2, status = 'running'
		 WHERE id = $3`,
		progress, currentStep, jobID,
	)
	if err != nil {
		return fmt.Errorf("update backup job progress: %w", err)
	}
	return nil
}

// Complete marks a backup job as completed.
func (r *BackupRepo) Complete(ctx context.Context, jobID string, backupPath string) error {
	now := time.Now().UTC()
	_, err := r.db.Exec(ctx,
		`UPDATE backup_jobs SET status = 'completed', progress = 100, backup_path = $1,
		 completed_at = $2, current_step = 'Done'
		 WHERE id = $3`,
		backupPath, now, jobID,
	)
	if err != nil {
		return fmt.Errorf("complete backup job: %w", err)
	}
	return nil
}

// Fail marks a backup job as failed with an error message.
func (r *BackupRepo) Fail(ctx context.Context, jobID string, errMsg string) error {
	now := time.Now().UTC()
	_, err := r.db.Exec(ctx,
		`UPDATE backup_jobs SET status = 'failed', error_message = $1,
		 completed_at = $2
		 WHERE id = $3`,
		errMsg, now, jobID,
	)
	if err != nil {
		return fmt.Errorf("fail backup job: %w", err)
	}
	return nil
}

// LatestCompleted returns the completed_at timestamp of the most recent
// successfully completed backup ("create" action only, so a restore job never
// counts as a successful backup). Returns (nil, nil) when no backup has ever
// completed. Used by the health monitor to detect stale/absent backups.
func (r *BackupRepo) LatestCompleted(ctx context.Context) (*time.Time, error) {
	var completedAt time.Time
	err := r.db.QueryRow(ctx,
		`SELECT completed_at FROM backup_jobs
		 WHERE status = 'completed' AND action = 'create' AND completed_at IS NOT NULL
		 ORDER BY completed_at DESC LIMIT 1`,
	).Scan(&completedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("latest completed backup: %w", err)
	}
	return &completedAt, nil
}

// FailIncomplete marks every non-terminal backup job (status 'pending' or
// 'running') as failed. Run once synchronously at startup: the manager is a
// single writer, so any job still pending/running at boot was orphaned by a
// crash or restart and will never complete. Returns the number of rows updated.
func (r *BackupRepo) FailIncomplete(ctx context.Context, reason string) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`UPDATE backup_jobs SET status = 'failed', error_message = $1, completed_at = $2
		 WHERE status IN ('pending', 'running')`,
		reason, time.Now().UTC(),
	)
	if err != nil {
		return 0, fmt.Errorf("fail incomplete backup jobs: %w", err)
	}
	return tag.RowsAffected(), nil
}

// GetByID returns a backup job by its ID.
func (r *BackupRepo) GetByID(ctx context.Context, jobID string) (*BackupJob, error) {
	var job BackupJob
	err := r.db.QueryRow(ctx,
		`SELECT id, action, status, backup_path, progress, current_step,
		        error_message, started_at, completed_at, triggered_by
		 FROM backup_jobs WHERE id = $1`, jobID,
	).Scan(
		&job.ID, &job.Action, &job.Status, &job.BackupPath, &job.Progress,
		&job.CurrentStep, &job.ErrorMessage, &job.StartedAt, &job.CompletedAt,
		&job.TriggeredBy,
	)
	if err != nil {
		return nil, fmt.Errorf("get backup job: %w", err)
	}
	return &job, nil
}

// List returns recent backup jobs ordered by started_at descending.
func (r *BackupRepo) List(ctx context.Context, limit int) ([]BackupJob, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := r.db.Query(ctx,
		`SELECT id, action, status, backup_path, progress, current_step,
		        error_message, started_at, completed_at, triggered_by
		 FROM backup_jobs ORDER BY started_at DESC LIMIT $1`, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("list backup jobs: %w", err)
	}
	defer rows.Close()

	var jobs []BackupJob
	for rows.Next() {
		var job BackupJob
		if err := rows.Scan(
			&job.ID, &job.Action, &job.Status, &job.BackupPath, &job.Progress,
			&job.CurrentStep, &job.ErrorMessage, &job.StartedAt, &job.CompletedAt,
			&job.TriggeredBy,
		); err != nil {
			return nil, fmt.Errorf("scan backup job: %w", err)
		}
		jobs = append(jobs, job)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate backup jobs: %w", err)
	}

	return jobs, nil
}
