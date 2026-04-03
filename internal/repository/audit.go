package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// AuditEntry represents an audit log record.
type AuditEntry struct {
	ID           string          `json:"id"`
	AdminID      *string         `json:"admin_id,omitempty"`
	Action       string          `json:"action"`
	ResourceType string          `json:"resource_type"`
	ResourceID   *string         `json:"resource_id,omitempty"`
	Details      json.RawMessage `json:"details,omitempty"`
	IPAddress    *string         `json:"ip_address,omitempty"`
	CreatedAt    time.Time       `json:"created_at"`
}

// AuditRepo handles audit log operations.
type AuditRepo struct {
	db *pgxpool.Pool
}

// NewAuditRepo creates a new audit repository.
func NewAuditRepo(db *pgxpool.Pool) *AuditRepo {
	return &AuditRepo{db: db}
}

// Log records an audit entry. action follows the pattern "resource.verb"
// (e.g., "domain.create", "mailbox.delete", "auth.login").
func (r *AuditRepo) Log(ctx context.Context, adminID *string, action, resourceType string, resourceID *string, details any, ipAddress *string) error {
	var detailsJSON []byte
	if details != nil {
		var err error
		detailsJSON, err = json.Marshal(details)
		if err != nil {
			return fmt.Errorf("marshal audit details: %w", err)
		}
	}

	_, err := r.db.Exec(ctx,
		`INSERT INTO audit_log (id, admin_id, action, resource_type, resource_id, details, ip_address, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		types.NewUUIDv7(), adminID, action, resourceType, resourceID, detailsJSON, ipAddress, time.Now().UTC(),
	)
	if err != nil {
		return fmt.Errorf("insert audit entry: %w", err)
	}
	return nil
}

// ListByResource returns audit entries for a specific resource.
func (r *AuditRepo) ListByResource(ctx context.Context, resourceType string, resourceID string, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(ctx,
		`SELECT id, admin_id, action, resource_type, resource_id, details, ip_address, created_at
		 FROM audit_log WHERE resource_type = $1 AND resource_id = $2
		 ORDER BY created_at DESC LIMIT $3`, resourceType, resourceID, limit)
	if err != nil {
		return nil, fmt.Errorf("list audit by resource: %w", err)
	}
	defer rows.Close()

	return scanAuditRows(rows)
}

// ListRecent returns the most recent audit entries.
func (r *AuditRepo) ListRecent(ctx context.Context, limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(ctx,
		`SELECT id, admin_id, action, resource_type, resource_id, details, ip_address, created_at
		 FROM audit_log ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list recent audit: %w", err)
	}
	defer rows.Close()

	return scanAuditRows(rows)
}

// ListPaginated returns audit entries with cursor pagination and optional filters.
func (r *AuditRepo) ListPaginated(ctx context.Context, action, resourceType, adminID string, params PaginationParams) ([]AuditEntry, error) {
	limit := params.Limit
	if limit <= 0 {
		limit = 50
	}

	query := `SELECT id, admin_id, action, resource_type, resource_id, details, ip_address, created_at
		 FROM audit_log WHERE 1=1`
	args := []any{}
	argIdx := 1

	if action != "" {
		query += fmt.Sprintf(" AND action = $%d", argIdx)
		args = append(args, action)
		argIdx++
	}
	if resourceType != "" {
		query += fmt.Sprintf(" AND resource_type = $%d", argIdx)
		args = append(args, resourceType)
		argIdx++
	}
	if adminID != "" {
		query += fmt.Sprintf(" AND admin_id = $%d", argIdx)
		args = append(args, adminID)
		argIdx++
	}
	if params.Cursor != nil {
		query += fmt.Sprintf(" AND created_at < $%d", argIdx)
		args = append(args, *params.Cursor)
		argIdx++
	}

	query += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", argIdx)
	args = append(args, limit+1)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list audit paginated: %w", err)
	}
	defer rows.Close()

	return scanAuditRows(rows)
}

// DeleteOlderThan removes audit entries created before the given time
// and returns the number of rows deleted.
func (r *AuditRepo) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM audit_log WHERE created_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("delete old audit entries: %w", err)
	}
	return tag.RowsAffected(), nil
}

func scanAuditRows(rows interface {
	Next() bool
	Scan(dest ...any) error
}) ([]AuditEntry, error) {
	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var ip *net.IP
		if err := rows.Scan(&e.ID, &e.AdminID, &e.Action, &e.ResourceType, &e.ResourceID, &e.Details, &ip, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan audit entry: %w", err)
		}
		if ip != nil {
			s := ip.String()
			e.IPAddress = &s
		}
		entries = append(entries, e)
	}
	return entries, nil
}
