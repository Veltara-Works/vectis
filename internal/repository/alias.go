package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// Alias represents an email alias.
type Alias struct {
	ID              string    `json:"id"`
	DomainID        string    `json:"domain_id"`
	SourceLocalPart string    `json:"source_local_part"`
	Destination     string    `json:"destination"`
	Active          bool      `json:"active"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// AliasCreate holds fields for creating an alias.
type AliasCreate struct {
	DomainID        string
	SourceLocalPart string
	Destination     string
}

// AliasUpdate holds fields for updating an alias.
type AliasUpdate struct {
	Destination *string
	Active      *bool
}

// AliasRepo handles alias CRUD operations.
type AliasRepo struct {
	db *pgxpool.Pool
}

// NewAliasRepo creates a new alias repository.
func NewAliasRepo(db *pgxpool.Pool) *AliasRepo {
	return &AliasRepo{db: db}
}

// Create inserts a new alias.
func (r *AliasRepo) Create(ctx context.Context, input AliasCreate) (*Alias, error) {
	a := &Alias{
		ID:              types.NewUUIDv7(),
		DomainID:        input.DomainID,
		SourceLocalPart: input.SourceLocalPart,
		Destination:     input.Destination,
		Active:          true,
	}

	now := time.Now().UTC()
	a.CreatedAt = now
	a.UpdatedAt = now

	_, err := r.db.Exec(ctx,
		`INSERT INTO aliases (id, domain_id, source_local_part, destination, active, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		a.ID, a.DomainID, a.SourceLocalPart, a.Destination, a.Active, a.CreatedAt, a.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert alias: %w", err)
	}
	return a, nil
}

// GetByID fetches an alias by its UUID.
func (r *AliasRepo) GetByID(ctx context.Context, id string) (*Alias, error) {
	a := &Alias{}
	err := r.db.QueryRow(ctx,
		`SELECT id, domain_id, source_local_part, destination, active, created_at, updated_at
		 FROM aliases WHERE id = $1`, id,
	).Scan(&a.ID, &a.DomainID, &a.SourceLocalPart, &a.Destination, &a.Active, &a.CreatedAt, &a.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get alias: %w", err)
	}
	return a, nil
}

// GetBySource fetches an alias by domain_id + source_local_part.
func (r *AliasRepo) GetBySource(ctx context.Context, domainID, sourceLocalPart string) (*Alias, error) {
	a := &Alias{}
	err := r.db.QueryRow(ctx,
		`SELECT id, domain_id, source_local_part, destination, active, created_at, updated_at
		 FROM aliases WHERE domain_id = $1 AND source_local_part = $2`, domainID, sourceLocalPart,
	).Scan(&a.ID, &a.DomainID, &a.SourceLocalPart, &a.Destination, &a.Active, &a.CreatedAt, &a.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get alias by source: %w", err)
	}
	return a, nil
}

// ListByDomain returns all aliases for a domain.
func (r *AliasRepo) ListByDomain(ctx context.Context, domainID string) ([]Alias, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, domain_id, source_local_part, destination, active, created_at, updated_at
		 FROM aliases WHERE domain_id = $1 ORDER BY source_local_part`, domainID)
	if err != nil {
		return nil, fmt.Errorf("list aliases: %w", err)
	}
	defer rows.Close()

	var aliases []Alias
	for rows.Next() {
		var a Alias
		if err := rows.Scan(&a.ID, &a.DomainID, &a.SourceLocalPart, &a.Destination, &a.Active, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan alias: %w", err)
		}
		aliases = append(aliases, a)
	}
	return aliases, nil
}

// ListByDomainPaginated returns aliases for a domain with cursor-based pagination.
// Results are ordered by created_at DESC. Fetches page.Limit+1 rows so the caller can detect has_more.
func (r *AliasRepo) ListByDomainPaginated(ctx context.Context, domainID string, page PaginationParams) ([]Alias, error) {
	cols := `id, domain_id, source_local_part, destination, active, created_at, updated_at`
	query := fmt.Sprintf(`SELECT %s FROM aliases WHERE domain_id = $1`, cols)
	args := []any{domainID}
	argIdx := 2

	if page.Cursor != nil {
		query += fmt.Sprintf(` AND created_at < $%d`, argIdx)
		args = append(args, *page.Cursor)
		argIdx++
	}

	query += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, argIdx)
	args = append(args, page.Limit+1)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list aliases paginated: %w", err)
	}
	defer rows.Close()

	var aliases []Alias
	for rows.Next() {
		var a Alias
		if err := rows.Scan(&a.ID, &a.DomainID, &a.SourceLocalPart, &a.Destination, &a.Active, &a.CreatedAt, &a.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan alias: %w", err)
		}
		aliases = append(aliases, a)
	}
	return aliases, nil
}

// Update modifies an alias's mutable fields.
func (r *AliasRepo) Update(ctx context.Context, id string, input AliasUpdate) (*Alias, error) {
	setClauses := []string{}
	args := []any{}
	argIdx := 1

	if input.Destination != nil {
		setClauses = append(setClauses, fmt.Sprintf("destination = $%d", argIdx))
		args = append(args, *input.Destination)
		argIdx++
	}
	if input.Active != nil {
		setClauses = append(setClauses, fmt.Sprintf("active = $%d", argIdx))
		args = append(args, *input.Active)
		argIdx++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argIdx))
	args = append(args, time.Now().UTC())
	argIdx++

	args = append(args, id)
	query := fmt.Sprintf("UPDATE aliases SET %s WHERE id = $%d",
		joinClauses(setClauses), argIdx)

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("update alias: %w", err)
	}
	if result.RowsAffected() == 0 {
		return nil, nil
	}
	return r.GetByID(ctx, id)
}

// Delete removes an alias.
func (r *AliasRepo) Delete(ctx context.Context, id string) (bool, error) {
	result, err := r.db.Exec(ctx, `DELETE FROM aliases WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete alias: %w", err)
	}
	return result.RowsAffected() > 0, nil
}
