package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// RBL check statuses. Unknown covers a refused query, a lookup error, or a
// list that failed its own test address; it must never be shown as clean.
const (
	RBLStatusListed  = "listed"
	RBLStatusClean   = "clean"
	RBLStatusUnknown = "unknown"
)

// RBLCheck represents a DNS blacklist check result.
type RBLCheck struct {
	ID        string    `json:"id"`
	IPAddress string    `json:"ip_address"`
	RBLName   string    `json:"rbl_name"`
	Status    string    `json:"status"`
	Listed    bool      `json:"listed"`
	Response  *string   `json:"response,omitempty"` // DNS answer when listed; reason when unknown
	CheckedAt time.Time `json:"checked_at"`
}

// rblCheckCols selects a check, deriving status from listed for rows written
// before migration 000025.
const rblCheckCols = `id, ip_address::text, rbl_name,
	COALESCE(status, CASE WHEN listed THEN 'listed' ELSE 'clean' END), listed, response, checked_at`

// RBLCheckRepo handles RBL check result storage.
type RBLCheckRepo struct {
	db *pgxpool.Pool
}

// NewRBLCheckRepo creates a new RBL check repository.
func NewRBLCheckRepo(db *pgxpool.Pool) *RBLCheckRepo {
	return &RBLCheckRepo{db: db}
}

// Create records a new RBL check result. status is one of the RBLStatus*
// constants; listed is written alongside it for pre-000025 readers. checkedAt
// is when the answer was observed, not when it is saved, so the latest-result
// queries (ordered by checked_at) stay right when two runs overlap.
func (r *RBLCheckRepo) Create(ctx context.Context, ipAddress, rblName, status string, response *string, checkedAt time.Time) (string, error) {
	switch status {
	case RBLStatusListed, RBLStatusClean, RBLStatusUnknown:
	default:
		return "", fmt.Errorf("insert rbl check: invalid status %q", status)
	}
	id := types.NewUUIDv7()
	_, err := r.db.Exec(ctx,
		`INSERT INTO rbl_checks (id, ip_address, rbl_name, status, listed, response, checked_at)
		 VALUES ($1, $2::inet, $3, $4, $5, $6, $7)`,
		id, ipAddress, rblName, status, status == RBLStatusListed, response, checkedAt,
	)
	if err != nil {
		return "", fmt.Errorf("insert rbl check: %w", err)
	}
	return id, nil
}

// GetLatestByIP returns the most recent check results for an IP address (one per RBL).
func (r *RBLCheckRepo) GetLatestByIP(ctx context.Context, ipAddress string) ([]RBLCheck, error) {
	rows, err := r.db.Query(ctx,
		`SELECT DISTINCT ON (rbl_name) `+rblCheckCols+`
		 FROM rbl_checks
		 WHERE ip_address = $1::inet
		 ORDER BY rbl_name, checked_at DESC`, ipAddress)
	if err != nil {
		return nil, fmt.Errorf("get latest rbl checks: %w", err)
	}
	defer rows.Close()

	var checks []RBLCheck
	for rows.Next() {
		var c RBLCheck
		if err := rows.Scan(&c.ID, &c.IPAddress, &c.RBLName, &c.Status, &c.Listed, &c.Response, &c.CheckedAt); err != nil {
			return nil, fmt.Errorf("scan rbl check: %w", err)
		}
		checks = append(checks, c)
	}
	return checks, nil
}

// GetListedIPs returns all IPs currently listed on any RBL (most recent check only).
func (r *RBLCheckRepo) GetListedIPs(ctx context.Context) ([]RBLCheck, error) {
	rows, err := r.db.Query(ctx,
		`SELECT DISTINCT ON (ip_address, rbl_name) `+rblCheckCols+`
		 FROM rbl_checks
		 WHERE listed = true
		 ORDER BY ip_address, rbl_name, checked_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("get listed ips: %w", err)
	}
	defer rows.Close()

	var checks []RBLCheck
	for rows.Next() {
		var c RBLCheck
		if err := rows.Scan(&c.ID, &c.IPAddress, &c.RBLName, &c.Status, &c.Listed, &c.Response, &c.CheckedAt); err != nil {
			return nil, fmt.Errorf("scan listed rbl check: %w", err)
		}
		checks = append(checks, c)
	}
	return checks, nil
}

// PruneOlderThan removes check results older than the given age.
func (r *RBLCheckRepo) PruneOlderThan(ctx context.Context, age time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-age)
	result, err := r.db.Exec(ctx,
		`DELETE FROM rbl_checks WHERE checked_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("prune rbl checks: %w", err)
	}
	return result.RowsAffected(), nil
}
