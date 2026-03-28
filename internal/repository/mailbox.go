package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// Mailbox represents an email mailbox.
type Mailbox struct {
	ID           string    `json:"id"`
	DomainID     string    `json:"domain_id"`
	LocalPart    string    `json:"local_part"`
	PasswordHash string    `json:"-"`
	DisplayName  *string   `json:"display_name,omitempty"`
	QuotaMB      int       `json:"quota_mb"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// MailboxCreate holds fields for creating a mailbox.
type MailboxCreate struct {
	DomainID     string
	LocalPart    string
	PasswordHash string
	DisplayName  *string
	QuotaMB      *int
}

// MailboxUpdate holds fields for updating a mailbox.
type MailboxUpdate struct {
	PasswordHash *string
	DisplayName  *string
	QuotaMB      *int
	Active       *bool
}

// MailboxRepo handles mailbox CRUD operations.
type MailboxRepo struct {
	db *pgxpool.Pool
}

// NewMailboxRepo creates a new mailbox repository.
func NewMailboxRepo(db *pgxpool.Pool) *MailboxRepo {
	return &MailboxRepo{db: db}
}

// Create inserts a new mailbox.
func (r *MailboxRepo) Create(ctx context.Context, input MailboxCreate) (*Mailbox, error) {
	m := &Mailbox{
		ID:           types.NewUUIDv7(),
		DomainID:     input.DomainID,
		LocalPart:    input.LocalPart,
		PasswordHash: input.PasswordHash,
		DisplayName:  input.DisplayName,
		QuotaMB:      1024,
		Active:       true,
	}
	if input.QuotaMB != nil {
		m.QuotaMB = *input.QuotaMB
	}

	now := time.Now().UTC()
	m.CreatedAt = now
	m.UpdatedAt = now

	_, err := r.db.Exec(ctx,
		`INSERT INTO mailboxes (id, domain_id, local_part, password_hash, display_name, quota_mb, active, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
		m.ID, m.DomainID, m.LocalPart, m.PasswordHash, m.DisplayName, m.QuotaMB, m.Active, m.CreatedAt, m.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("insert mailbox: %w", err)
	}
	return m, nil
}

// GetByID fetches a mailbox by its UUID.
func (r *MailboxRepo) GetByID(ctx context.Context, id string) (*Mailbox, error) {
	m := &Mailbox{}
	err := r.db.QueryRow(ctx,
		`SELECT id, domain_id, local_part, password_hash, display_name, quota_mb, active, created_at, updated_at
		 FROM mailboxes WHERE id = $1`, id,
	).Scan(&m.ID, &m.DomainID, &m.LocalPart, &m.PasswordHash, &m.DisplayName, &m.QuotaMB, &m.Active, &m.CreatedAt, &m.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get mailbox: %w", err)
	}
	return m, nil
}

// GetByEmail fetches a mailbox by local_part + domain_id.
func (r *MailboxRepo) GetByEmail(ctx context.Context, domainID, localPart string) (*Mailbox, error) {
	m := &Mailbox{}
	err := r.db.QueryRow(ctx,
		`SELECT id, domain_id, local_part, password_hash, display_name, quota_mb, active, created_at, updated_at
		 FROM mailboxes WHERE domain_id = $1 AND local_part = $2`, domainID, localPart,
	).Scan(&m.ID, &m.DomainID, &m.LocalPart, &m.PasswordHash, &m.DisplayName, &m.QuotaMB, &m.Active, &m.CreatedAt, &m.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get mailbox by email: %w", err)
	}
	return m, nil
}

// ListByDomain returns all mailboxes for a domain.
func (r *MailboxRepo) ListByDomain(ctx context.Context, domainID string) ([]Mailbox, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, domain_id, local_part, password_hash, display_name, quota_mb, active, created_at, updated_at
		 FROM mailboxes WHERE domain_id = $1 ORDER BY local_part`, domainID)
	if err != nil {
		return nil, fmt.Errorf("list mailboxes: %w", err)
	}
	defer rows.Close()

	var mailboxes []Mailbox
	for rows.Next() {
		var m Mailbox
		if err := rows.Scan(&m.ID, &m.DomainID, &m.LocalPart, &m.PasswordHash, &m.DisplayName, &m.QuotaMB, &m.Active, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan mailbox: %w", err)
		}
		mailboxes = append(mailboxes, m)
	}
	return mailboxes, nil
}

// ListByDomainPaginated returns mailboxes for a domain with cursor-based pagination.
// Results are ordered by created_at DESC. Fetches page.Limit+1 rows so the caller can detect has_more.
func (r *MailboxRepo) ListByDomainPaginated(ctx context.Context, domainID string, page PaginationParams) ([]Mailbox, error) {
	cols := `id, domain_id, local_part, password_hash, display_name, quota_mb, active, created_at, updated_at`
	query := fmt.Sprintf(`SELECT %s FROM mailboxes WHERE domain_id = $1`, cols)
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
		return nil, fmt.Errorf("list mailboxes paginated: %w", err)
	}
	defer rows.Close()

	var mailboxes []Mailbox
	for rows.Next() {
		var m Mailbox
		if err := rows.Scan(&m.ID, &m.DomainID, &m.LocalPart, &m.PasswordHash, &m.DisplayName, &m.QuotaMB, &m.Active, &m.CreatedAt, &m.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan mailbox: %w", err)
		}
		mailboxes = append(mailboxes, m)
	}
	return mailboxes, nil
}

// Update modifies a mailbox's mutable fields.
func (r *MailboxRepo) Update(ctx context.Context, id string, input MailboxUpdate) (*Mailbox, error) {
	setClauses := []string{}
	args := []any{}
	argIdx := 1

	if input.PasswordHash != nil {
		setClauses = append(setClauses, fmt.Sprintf("password_hash = $%d", argIdx))
		args = append(args, *input.PasswordHash)
		argIdx++
	}
	if input.DisplayName != nil {
		setClauses = append(setClauses, fmt.Sprintf("display_name = $%d", argIdx))
		args = append(args, *input.DisplayName)
		argIdx++
	}
	if input.QuotaMB != nil {
		setClauses = append(setClauses, fmt.Sprintf("quota_mb = $%d", argIdx))
		args = append(args, *input.QuotaMB)
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
	query := fmt.Sprintf("UPDATE mailboxes SET %s WHERE id = $%d",
		joinClauses(setClauses), argIdx)

	result, err := r.db.Exec(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("update mailbox: %w", err)
	}
	if result.RowsAffected() == 0 {
		return nil, nil
	}
	return r.GetByID(ctx, id)
}

// Delete removes a mailbox.
func (r *MailboxRepo) Delete(ctx context.Context, id string) (bool, error) {
	result, err := r.db.Exec(ctx, `DELETE FROM mailboxes WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete mailbox: %w", err)
	}
	return result.RowsAffected() > 0, nil
}
