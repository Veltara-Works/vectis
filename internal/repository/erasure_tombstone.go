package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// ErasureTombstone is the minimal suppression record left after a data
// subject's personal data is erased (GDPR Art.17). It exists so the startup
// reconciler can re-apply the erasure if a backup restore resurrects the
// subject's mailbox/mail/metadata. It carries no message content.
type ErasureTombstone struct {
	ID            string     `json:"id"`
	SubjectEmail  string     `json:"subject_email"`
	Domain        string     `json:"domain"`
	LocalPart     string     `json:"local_part"`
	ErasedAt      time.Time  `json:"erased_at"`
	ErasedBy      *string    `json:"erased_by,omitempty"`
	ReconciledAt  *time.Time `json:"reconciled_at,omitempty"`
	ReconcileRuns int        `json:"reconcile_runs"`
}

// ErasureTombstoneRepo handles erasure tombstone storage and lookup.
type ErasureTombstoneRepo struct {
	db *pgxpool.Pool
}

// NewErasureTombstoneRepo creates a new erasure tombstone repository.
func NewErasureTombstoneRepo(db *pgxpool.Pool) *ErasureTombstoneRepo {
	return &ErasureTombstoneRepo{db: db}
}

const erasureTombstoneCols = `id, subject_email, domain, local_part, erased_at, erased_by, reconciled_at, reconcile_runs`

func scanErasureTombstone(scan func(dest ...any) error) (*ErasureTombstone, error) {
	t := &ErasureTombstone{}
	err := scan(&t.ID, &t.SubjectEmail, &t.Domain, &t.LocalPart, &t.ErasedAt, &t.ErasedBy, &t.ReconciledAt, &t.ReconcileRuns)
	return t, err
}

// Upsert records (or refreshes) a tombstone for a subject. Erasing the same
// subject twice updates erased_at/erased_by rather than failing the unique
// constraint, so a re-run after a partial failure is safe.
func (r *ErasureTombstoneRepo) Upsert(ctx context.Context, subjectEmail, domain, localPart string, erasedBy *string) (*ErasureTombstone, error) {
	t := &ErasureTombstone{
		ID:           types.NewUUIDv7(),
		SubjectEmail: subjectEmail,
		Domain:       domain,
		LocalPart:    localPart,
		ErasedAt:     time.Now().UTC(),
		ErasedBy:     erasedBy,
	}
	err := r.db.QueryRow(ctx,
		`INSERT INTO erasure_tombstones (id, subject_email, domain, local_part, erased_at, erased_by, reconcile_runs)
		 VALUES ($1, $2, $3, $4, $5, $6, 0)
		 ON CONFLICT (subject_email) DO UPDATE
		   SET erased_at = EXCLUDED.erased_at, erased_by = EXCLUDED.erased_by
		 RETURNING `+erasureTombstoneCols, t.ID, t.SubjectEmail, t.Domain, t.LocalPart, t.ErasedAt, t.ErasedBy,
	).Scan(&t.ID, &t.SubjectEmail, &t.Domain, &t.LocalPart, &t.ErasedAt, &t.ErasedBy, &t.ReconciledAt, &t.ReconcileRuns)
	if err != nil {
		return nil, fmt.Errorf("upsert erasure tombstone: %w", err)
	}
	return t, nil
}

// GetBySubject fetches a tombstone by subject email, or nil if none exists.
func (r *ErasureTombstoneRepo) GetBySubject(ctx context.Context, subjectEmail string) (*ErasureTombstone, error) {
	t, err := scanErasureTombstone(r.db.QueryRow(ctx,
		`SELECT `+erasureTombstoneCols+` FROM erasure_tombstones WHERE subject_email = $1`, subjectEmail).Scan)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get erasure tombstone: %w", err)
	}
	return t, nil
}

// List returns all tombstones, oldest first.
func (r *ErasureTombstoneRepo) List(ctx context.Context) ([]ErasureTombstone, error) {
	rows, err := r.db.Query(ctx,
		`SELECT `+erasureTombstoneCols+` FROM erasure_tombstones ORDER BY erased_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("list erasure tombstones: %w", err)
	}
	defer rows.Close()

	var tombstones []ErasureTombstone
	for rows.Next() {
		t, err := scanErasureTombstone(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan erasure tombstone: %w", err)
		}
		tombstones = append(tombstones, *t)
	}
	return tombstones, nil
}

// MarkReconciled stamps a tombstone after a reconcile pass re-applied (or
// confirmed) the erasure and bumps its reconcile counter.
func (r *ErasureTombstoneRepo) MarkReconciled(ctx context.Context, id string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE erasure_tombstones SET reconciled_at = $1, reconcile_runs = reconcile_runs + 1 WHERE id = $2`,
		time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("mark erasure tombstone reconciled: %w", err)
	}
	return nil
}
