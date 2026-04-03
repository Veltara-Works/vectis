package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AdminDomain represents a mapping between a domain_admin and a domain.
type AdminDomain struct {
	AdminID   string    `json:"admin_id"`
	DomainID  string    `json:"domain_id"`
	CreatedAt time.Time `json:"created_at"`
}

// AdminDomainRepo handles admin-domain mapping operations.
type AdminDomainRepo struct {
	db *pgxpool.Pool
}

// NewAdminDomainRepo creates a new admin-domain repository.
func NewAdminDomainRepo(db *pgxpool.Pool) *AdminDomainRepo {
	return &AdminDomainRepo{db: db}
}

// Assign grants a domain_admin access to a domain.
func (r *AdminDomainRepo) Assign(ctx context.Context, adminID, domainID string) error {
	_, err := r.db.Exec(ctx,
		`INSERT INTO admin_domains (admin_id, domain_id) VALUES ($1, $2)
		 ON CONFLICT (admin_id, domain_id) DO NOTHING`,
		adminID, domainID)
	if err != nil {
		return fmt.Errorf("assign admin domain: %w", err)
	}
	return nil
}

// Revoke removes a domain_admin's access to a domain.
func (r *AdminDomainRepo) Revoke(ctx context.Context, adminID, domainID string) error {
	_, err := r.db.Exec(ctx,
		`DELETE FROM admin_domains WHERE admin_id = $1 AND domain_id = $2`,
		adminID, domainID)
	if err != nil {
		return fmt.Errorf("revoke admin domain: %w", err)
	}
	return nil
}

// ListDomainIDs returns the domain IDs assigned to an admin.
func (r *AdminDomainRepo) ListDomainIDs(ctx context.Context, adminID string) ([]string, error) {
	rows, err := r.db.Query(ctx,
		`SELECT domain_id FROM admin_domains WHERE admin_id = $1`, adminID)
	if err != nil {
		return nil, fmt.Errorf("list admin domains: %w", err)
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("scan admin domain: %w", err)
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// HasAccess returns true if the admin has been assigned the given domain.
func (r *AdminDomainRepo) HasAccess(ctx context.Context, adminID, domainID string) (bool, error) {
	var exists bool
	err := r.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM admin_domains WHERE admin_id = $1 AND domain_id = $2)`,
		adminID, domainID).Scan(&exists)
	if err != nil {
		return false, fmt.Errorf("check admin domain access: %w", err)
	}
	return exists, nil
}

// ReplaceAll sets the admin's domain assignments, replacing any existing ones.
func (r *AdminDomainRepo) ReplaceAll(ctx context.Context, adminID string, domainIDs []string) error {
	tx, err := r.db.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx)

	_, err = tx.Exec(ctx, `DELETE FROM admin_domains WHERE admin_id = $1`, adminID)
	if err != nil {
		return fmt.Errorf("clear admin domains: %w", err)
	}

	for _, domainID := range domainIDs {
		_, err = tx.Exec(ctx,
			`INSERT INTO admin_domains (admin_id, domain_id) VALUES ($1, $2)`,
			adminID, domainID)
		if err != nil {
			return fmt.Errorf("insert admin domain: %w", err)
		}
	}

	return tx.Commit(ctx)
}
