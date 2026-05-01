package repository

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// Domain represents a mail domain.
type Domain struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Active             bool      `json:"active"`
	DKIMEnabled        bool      `json:"dkim_enabled"`
	DKIMSelector       string    `json:"dkim_selector"`
	DKIMKeyPath        *string   `json:"dkim_key_path,omitempty"`
	SpamThreshold      float64   `json:"spam_threshold"`
	RejectThreshold    *float64  `json:"reject_threshold,omitempty"`
	GreylistEnabled    *bool     `json:"greylist_enabled,omitempty"`
	MaxMailboxes       *int      `json:"max_mailboxes,omitempty"`
	VerificationStatus string    `json:"verification_status"`
	VerificationToken  *string   `json:"verification_token,omitempty"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}

// DomainCreate holds fields for creating a domain.
type DomainCreate struct {
	Name            string
	SpamThreshold   *float64
	RejectThreshold *float64
	GreylistEnabled *bool
	MaxMailboxes    *int
}

// DomainUpdate holds fields for updating a domain.
type DomainUpdate struct {
	Active             *bool
	DKIMEnabled        *bool
	DKIMSelector       *string
	DKIMKeyPath        *string
	SpamThreshold      *float64
	RejectThreshold    *float64
	GreylistEnabled    *bool
	MaxMailboxes       *int
	VerificationStatus *string
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
	token := types.NewVerificationToken()
	d := &Domain{
		ID:                 types.NewUUIDv7(),
		Name:               input.Name,
		Active:             true,
		DKIMEnabled:        true,
		DKIMSelector:       "default",
		SpamThreshold:      15.0,
		VerificationStatus: "pending",
		VerificationToken:  &token,
	}
	if input.SpamThreshold != nil {
		d.SpamThreshold = *input.SpamThreshold
	}
	if input.RejectThreshold != nil {
		d.RejectThreshold = input.RejectThreshold
	}
	if input.GreylistEnabled != nil {
		d.GreylistEnabled = input.GreylistEnabled
	}
	if input.MaxMailboxes != nil {
		d.MaxMailboxes = input.MaxMailboxes
	}

	now := time.Now().UTC()
	d.CreatedAt = now
	d.UpdatedAt = now

	_, err := r.db.Exec(ctx,
		`INSERT INTO domains (id, name, active, dkim_enabled, dkim_selector, spam_threshold, reject_threshold, greylist_enabled, max_mailboxes, verification_status, verification_token, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		d.ID, d.Name, d.Active, d.DKIMEnabled, d.DKIMSelector, d.SpamThreshold, d.RejectThreshold, d.GreylistEnabled, d.MaxMailboxes, d.VerificationStatus, d.VerificationToken, d.CreatedAt, d.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert domain: %w", err)
	}
	return d, nil
}

// domainCols is the standard column list for domain SELECT queries.
const domainCols = `id, name, active, dkim_enabled, dkim_selector, dkim_key_path,
	spam_threshold, reject_threshold, greylist_enabled, max_mailboxes, verification_status, verification_token, created_at, updated_at`

// scanDomain scans a row into a Domain struct matching domainCols order.
func scanDomain(scan func(dest ...any) error) (*Domain, error) {
	d := &Domain{}
	err := scan(&d.ID, &d.Name, &d.Active, &d.DKIMEnabled, &d.DKIMSelector, &d.DKIMKeyPath,
		&d.SpamThreshold, &d.RejectThreshold, &d.GreylistEnabled, &d.MaxMailboxes, &d.VerificationStatus, &d.VerificationToken, &d.CreatedAt, &d.UpdatedAt)
	return d, err
}

// GetByID fetches a domain by its UUID.
func (r *DomainRepo) GetByID(ctx context.Context, id string) (*Domain, error) {
	d, err := scanDomain(r.db.QueryRow(ctx,
		`SELECT `+domainCols+` FROM domains WHERE id = $1`, id,
	).Scan)
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
	d, err := scanDomain(r.db.QueryRow(ctx,
		`SELECT `+domainCols+` FROM domains WHERE name = $1`, name,
	).Scan)
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
	query := `SELECT ` + domainCols + ` FROM domains`
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
		d, err := scanDomain(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		domains = append(domains, *d)
	}
	return domains, nil
}

// ListPaginated returns domains with cursor-based pagination, optionally filtered by active status.
// Results are ordered by created_at DESC. Fetches page.Limit+1 rows so the caller can detect has_more.
func (r *DomainRepo) ListPaginated(ctx context.Context, activeOnly *bool, page PaginationParams) ([]Domain, error) {
	query := fmt.Sprintf(`SELECT %s FROM domains`, domainCols)

	var conditions []string
	var args []any
	argIdx := 1

	if activeOnly != nil {
		conditions = append(conditions, fmt.Sprintf("active = $%d", argIdx))
		args = append(args, *activeOnly)
		argIdx++
	}
	if page.Cursor != nil {
		conditions = append(conditions, fmt.Sprintf("created_at < $%d", argIdx))
		args = append(args, *page.Cursor)
		argIdx++
	}

	if len(conditions) > 0 {
		query += " WHERE " + joinConditions(conditions)
	}

	query += fmt.Sprintf(` ORDER BY created_at DESC LIMIT $%d`, argIdx)
	args = append(args, page.Limit+1)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list domains paginated: %w", err)
	}
	defer rows.Close()

	var domains []Domain
	for rows.Next() {
		d, err := scanDomain(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		domains = append(domains, *d)
	}
	return domains, nil
}

// ListByIDs returns domains matching the given IDs, ordered by created_at DESC.
func (r *DomainRepo) ListByIDs(ctx context.Context, ids []string) ([]Domain, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	// Build $1, $2, ... placeholders.
	placeholders := make([]string, len(ids))
	args := make([]any, len(ids))
	for i, id := range ids {
		placeholders[i] = fmt.Sprintf("$%d", i+1)
		args[i] = id
	}

	query := fmt.Sprintf(`SELECT %s FROM domains WHERE id IN (%s) ORDER BY created_at DESC`,
		domainCols, strings.Join(placeholders, ", "))

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list domains by ids: %w", err)
	}
	defer rows.Close()

	var domains []Domain
	for rows.Next() {
		d, err := scanDomain(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan domain: %w", err)
		}
		domains = append(domains, *d)
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
	if input.RejectThreshold != nil {
		setClauses = append(setClauses, fmt.Sprintf("reject_threshold = $%d", argIdx))
		args = append(args, *input.RejectThreshold)
		argIdx++
	}
	if input.GreylistEnabled != nil {
		setClauses = append(setClauses, fmt.Sprintf("greylist_enabled = $%d", argIdx))
		args = append(args, *input.GreylistEnabled)
		argIdx++
	}
	if input.MaxMailboxes != nil {
		setClauses = append(setClauses, fmt.Sprintf("max_mailboxes = $%d", argIdx))
		args = append(args, *input.MaxMailboxes)
		argIdx++
	}
	if input.VerificationStatus != nil {
		setClauses = append(setClauses, fmt.Sprintf("verification_status = $%d", argIdx))
		args = append(args, *input.VerificationStatus)
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

// Count returns the total number of domains, optionally filtered by active state.
// Used for Free-tier resource cap enforcement (3 domains max).
func (r *DomainRepo) Count(ctx context.Context, activeOnly *bool) (int, error) {
	var count int
	var err error
	if activeOnly == nil {
		err = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM domains`).Scan(&count)
	} else {
		err = r.db.QueryRow(ctx, `SELECT COUNT(*) FROM domains WHERE active = $1`, *activeOnly).Scan(&count)
	}
	if err != nil {
		return 0, fmt.Errorf("count domains: %w", err)
	}
	return count, nil
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

func joinConditions(conditions []string) string {
	result := ""
	for i, c := range conditions {
		if i > 0 {
			result += " AND "
		}
		result += c
	}
	return result
}
