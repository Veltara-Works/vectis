package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// Domain represents a mail domain.
type Domain struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	Active        bool      `json:"active"`
	DKIMEnabled   bool      `json:"dkim_enabled"`
	DKIMSelector  string    `json:"dkim_selector"`
	DKIMKeyPath   *string   `json:"dkim_key_path,omitempty"`
	SpamThreshold float64   `json:"spam_threshold"`
	MaxMailboxes  *int      `json:"max_mailboxes,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// DomainCreate holds fields for creating a domain.
type DomainCreate struct {
	Name          string
	SpamThreshold *float64
	MaxMailboxes  *int
}

// DomainUpdate holds fields for updating a domain.
type DomainUpdate struct {
	Active        *bool
	DKIMEnabled   *bool
	DKIMSelector  *string
	DKIMKeyPath   *string
	SpamThreshold *float64
	MaxMailboxes  *int
}

// DomainRepo handles domain CRUD operations.
type DomainRepo struct {
	db *pgxpool.Pool
}

// NewDomainRepo creates a new domain repository.
func NewDomainRepo(db *pgxpool.Pool) *DomainRepo {
	return &DomainRepo{db: db}
}

// Create inserts a new domain.
func (r *DomainRepo) Create(ctx context.Context, input DomainCreate) (*Domain, error) {
	d := &Domain{
		ID:            types.NewUUIDv7(),
		Name:          input.Name,
		Active:        true,
		DKIMEnabled:   true,
		DKIMSelector:  "default",
		SpamThreshold: 15.0,
	}
	if input.SpamThreshold != nil {
		d.SpamThreshold = *input.SpamThreshold
	}
	if input.MaxMailboxes != nil {
		d.MaxMailboxes = input.MaxMailboxes
	}

	now := time.Now().UTC()
	d.CreatedAt = now
	d.UpdatedAt = now

	_, err := r.db.Exec(ctx,
		`INSERT INTO domains (id, name, active, dkim_enabled, dkim_selector, spam_threshold, max_mailboxes, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		d.ID, d.Name, d.Active, d.DKIMEnabled, d.DKIMSelector, d.SpamThreshold, d.MaxMailboxes, d.CreatedAt, d.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert domain: %w", err)
	}
	return d, nil
}

// GetByID fetches a domain by its UUID.
func (r *DomainRepo) GetByID(ctx context.Context, id string) (*Domain, error) {
	d := &Domain{}
	err := r.db.QueryRow(ctx,
		`SELECT id, name, active, dkim_enabled, dkim_selector, dkim_key_path,
		        spam_threshold, max_mailboxes, created_at, updated_at
		 FROM domains WHERE id = $1`, id,
	).Scan(&d.ID, &d.Name, &d.Active, &d.DKIMEnabled, &d.DKIMSelector, &d.DKIMKeyPath,
		&d.SpamThreshold, &d.MaxMailboxes, &d.CreatedAt, &d.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get domain: %w", err)
	}
	return d, nil
}

// GetByName fetches a domain by its name.
func (r *DomainRepo) GetByName(ctx context.Context, name string) (*Domain, error) {
	d := &Domain{}
	err := r.db.QueryRow(ctx,
		`SELECT id, name, active, dkim_enabled, dkim_selector, dkim_key_path,
		        spam_threshold, max_mailboxes, created_at, updated_at
		 FROM domains WHERE name = $1`, name,
	).Scan(&d.ID, &d.Name, &d.Active, &d.DKIMEnabled, &d.DKIMSelector, &d.DKIMKeyPath,
		&d.SpamThreshold, &d.MaxMailboxes, &d.CreatedAt, &d.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get domain by name: %w", err)
	}
	return d, nil
}

// List returns all domains, optionally filtered by active status.
func (r *DomainRepo) List(ctx context.Context, activeOnly *bool) ([]Domain, error) {
	query := `SELECT id, name, active, dkim_enabled, dkim_selector, dkim_key_path,
	                 spam_threshold, max_mailboxes, created_at, updated_at
	          FROM domains`
	var args []any
	if activeOnly != nil {
		query += ` WHERE active = $1`
		args = append(args, *activeOnly)
	}
	query += ` ORDER BY name`

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list domains: %w", err)
	}
	defer rows.Close()

	var domains []Domain
	for rows.Next() {
		var d Domain
		if err := rows.Scan(&d.ID, &d.Name, &d.Active, &d.DKIMEnabled, &d.DKIMSelector, &d.DKIMKeyPath,
			&d.SpamThreshold, &d.MaxMailboxes, &d.CreatedAt, &d.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		domains = append(domains, d)
	}
	return domains, nil
}

// Update modifies a domain's mutable fields.
func (r *DomainRepo) Update(ctx context.Context, id string, input DomainUpdate) (*Domain, error) {
	// Build dynamic SET clause.
	setClauses := []string{}
	args := []any{}
	argIdx := 1

	if input.Active != nil {
		setClauses = append(setClauses, fmt.Sprintf("active = $%d", argIdx))
		args = append(args, *input.Active)
		argIdx++
	}
	if input.DKIMEnabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("dkim_enabled = $%d", argIdx))
		args = append(args, *input.DKIMEnabled)
		argIdx++
	}
	if input.DKIMSelector != nil {
		setClauses = append(setClauses, fmt.Sprintf("dkim_selector = $%d", argIdx))
		args = append(args, *input.DKIMSelector)
		argIdx++
	}
	if input.DKIMKeyPath != nil {
		setClauses = append(setClauses, fmt.Sprintf("dkim_key_path = $%d", argIdx))
		args = append(args, *input.DKIMKeyPath)
		argIdx++
	}
	if input.SpamThreshold != nil {
		setClauses = append(setClauses, fmt.Sprintf("spam_threshold = $%d", argIdx))
		args = append(args, *input.SpamThreshold)
		argIdx++
	}
	if input.MaxMailboxes != nil {
		setClauses = append(setClauses, fmt.Sprintf("max_mailboxes = $%d", argIdx))
		args = append(args, *input.MaxMailboxes)
		argIdx++
	}

	if len(setClauses) == 0 {
		return r.GetByID(ctx, id)
	}

	// Always update updated_at.
	setClauses = append(setClauses, fmt.Sprintf("updated_at = $%d", argIdx))
	args = append(args, time.Now().UTC())
	argIdx++

	args = append(args, id)
	query := fmt.Sprintf("UPDATE domains SET %s WHERE id = $%d",
		joinClauses(setClauses), argIdx)

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("update domain: %w", err)
	}
	if result.RowsAffected() == 0 {
		return nil, nil
	}
	return r.GetByID(ctx, id)
}

// Delete removes a domain. Returns false if not found.
func (r *DomainRepo) Delete(ctx context.Context, id string) (bool, error) {
	result, err := r.db.Exec(ctx, `DELETE FROM domains WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete domain: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

// CountMailboxes returns the number of mailboxes in a domain.
func (r *DomainRepo) CountMailboxes(ctx context.Context, domainID string) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM mailboxes WHERE domain_id = $1`, domainID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count mailboxes: %w", err)
	}
	return count, nil
}

// CountAliases returns the number of aliases in a domain.
func (r *DomainRepo) CountAliases(ctx context.Context, domainID string) (int, error) {
	var count int
	err := r.db.QueryRow(ctx, `SELECT COUNT(*) FROM aliases WHERE domain_id = $1`, domainID).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count aliases: %w", err)
	}
	return count, nil
}

func joinClauses(clauses []string) string {
	result := ""
	for i, c := range clauses {
		if i > 0 {
			result += ", "
		}
		result += c
	}
	return result
}
