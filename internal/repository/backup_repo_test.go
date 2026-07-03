//go:build integration

package repository_test

import (
	"context"
	"testing"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// resetBackupJobs clears the shared backup_jobs table so these tests, which
// query/mutate the whole table (LatestCompleted, FailIncomplete), are not
// perturbed by rows left over from other runs. backup_jobs has no per-tenant
// scoping, so a full clear is the honest isolation boundary here.
func resetBackupJobs(t *testing.T, ctx context.Context) {
	t.Helper()
	if _, err := testPool.Exec(ctx, `DELETE FROM backup_jobs`); err != nil {
		t.Fatalf("reset backup_jobs: %v", err)
	}
}

func TestBackupRepo_LatestCompleted(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewBackupRepo(testPool)
	resetBackupJobs(t, ctx)

	t.Run("nil when none completed", func(t *testing.T) {
		got, err := repo.LatestCompleted(ctx)
		if err != nil {
			t.Fatalf("LatestCompleted: %v", err)
		}
		if got != nil {
			t.Errorf("LatestCompleted on empty table = %v, want nil", got)
		}
	})

	t.Run("pending/running/failed do not count", func(t *testing.T) {
		resetBackupJobs(t, ctx)
		// pending
		if _, err := repo.Create(ctx, "create", nil); err != nil {
			t.Fatalf("create pending: %v", err)
		}
		// running
		running, err := repo.Create(ctx, "create", nil)
		if err != nil {
			t.Fatalf("create running: %v", err)
		}
		if err := repo.UpdateProgress(ctx, running.ID, 50, "working"); err != nil {
			t.Fatalf("update running: %v", err)
		}
		// failed
		failed, err := repo.Create(ctx, "create", nil)
		if err != nil {
			t.Fatalf("create failed: %v", err)
		}
		if err := repo.Fail(ctx, failed.ID, "boom"); err != nil {
			t.Fatalf("fail: %v", err)
		}

		got, err := repo.LatestCompleted(ctx)
		if err != nil {
			t.Fatalf("LatestCompleted: %v", err)
		}
		if got != nil {
			t.Errorf("LatestCompleted with no completed rows = %v, want nil", got)
		}
	})

	t.Run("returns newest completed create; ignores restore", func(t *testing.T) {
		resetBackupJobs(t, ctx)

		first, err := repo.Create(ctx, "create", nil)
		if err != nil {
			t.Fatalf("create first: %v", err)
		}
		if err := repo.Complete(ctx, first.ID, "/backups/first.tar.gz.enc"); err != nil {
			t.Fatalf("complete first: %v", err)
		}

		second, err := repo.Create(ctx, "create", nil)
		if err != nil {
			t.Fatalf("create second: %v", err)
		}
		if err := repo.Complete(ctx, second.ID, "/backups/second.tar.gz.enc"); err != nil {
			t.Fatalf("complete second: %v", err)
		}

		// A completed RESTORE must not count as a successful backup, even though
		// it completes latest.
		restore, err := repo.Create(ctx, "restore", nil)
		if err != nil {
			t.Fatalf("create restore: %v", err)
		}
		if err := repo.Complete(ctx, restore.ID, "/backups/restored"); err != nil {
			t.Fatalf("complete restore: %v", err)
		}

		got, err := repo.LatestCompleted(ctx)
		if err != nil {
			t.Fatalf("LatestCompleted: %v", err)
		}
		if got == nil {
			t.Fatal("LatestCompleted = nil, want the second create's completed_at")
		}
		// Fetch the second job to compare its completed_at.
		secondJob, err := repo.GetByID(ctx, second.ID)
		if err != nil {
			t.Fatalf("GetByID second: %v", err)
		}
		if !got.Equal(*secondJob.CompletedAt) {
			t.Errorf("LatestCompleted = %v, want second create's %v", *got, *secondJob.CompletedAt)
		}
	})
}

func TestBackupRepo_FailIncomplete(t *testing.T) {
	ctx := context.Background()
	repo := repository.NewBackupRepo(testPool)
	resetBackupJobs(t, ctx)

	// pending
	pending, err := repo.Create(ctx, "create", nil)
	if err != nil {
		t.Fatalf("create pending: %v", err)
	}
	// running
	running, err := repo.Create(ctx, "create", nil)
	if err != nil {
		t.Fatalf("create running: %v", err)
	}
	if err := repo.UpdateProgress(ctx, running.ID, 30, "archiving"); err != nil {
		t.Fatalf("update running: %v", err)
	}
	// already completed — must be left untouched
	done, err := repo.Create(ctx, "create", nil)
	if err != nil {
		t.Fatalf("create done: %v", err)
	}
	if err := repo.Complete(ctx, done.ID, "/backups/done.tar.gz.enc"); err != nil {
		t.Fatalf("complete done: %v", err)
	}

	n, err := repo.FailIncomplete(ctx, "server restarted; job interrupted")
	if err != nil {
		t.Fatalf("FailIncomplete: %v", err)
	}
	if n != 2 {
		t.Errorf("FailIncomplete affected %d rows, want 2 (pending+running)", n)
	}

	// pending and running are now failed with the reason set.
	for _, id := range []string{pending.ID, running.ID} {
		job, err := repo.GetByID(ctx, id)
		if err != nil {
			t.Fatalf("GetByID %s: %v", id, err)
		}
		if job.Status != "failed" {
			t.Errorf("job %s status = %q, want failed", id, job.Status)
		}
		if job.ErrorMessage == nil || *job.ErrorMessage != "server restarted; job interrupted" {
			t.Errorf("job %s error_message = %v, want interrupted reason", id, job.ErrorMessage)
		}
		if job.CompletedAt == nil {
			t.Errorf("job %s completed_at is nil, want set", id)
		}
	}

	// completed job untouched.
	doneJob, err := repo.GetByID(ctx, done.ID)
	if err != nil {
		t.Fatalf("GetByID done: %v", err)
	}
	if doneJob.Status != "completed" {
		t.Errorf("completed job status = %q, want completed (untouched)", doneJob.Status)
	}

	// second call is a no-op (idempotent) — nothing left non-terminal.
	n2, err := repo.FailIncomplete(ctx, "again")
	if err != nil {
		t.Fatalf("FailIncomplete 2nd: %v", err)
	}
	if n2 != 0 {
		t.Errorf("second FailIncomplete affected %d rows, want 0", n2)
	}
}
