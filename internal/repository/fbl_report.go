package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// FBLReport represents an ISP feedback loop (ARF) complaint report.
type FBLReport struct {
	ID                string          `json:"id"`
	DomainID          *string         `json:"domain_id,omitempty"`
	MailboxID         *string         `json:"mailbox_id,omitempty"`
	OriginalMessageID *string         `json:"original_message_id,omitempty"`
	ReporterDomain    string          `json:"reporter_domain"`
	ComplaintType     string          `json:"complaint_type"`
	FeedbackID        *string         `json:"feedback_id,omitempty"`
	Details           json.RawMessage `json:"details,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
}

// FBLReportRepo handles FBL complaint storage and retrieval.
type FBLReportRepo struct {
	db *pgxpool.Pool
}

// NewFBLReportRepo creates a new FBL report repository.
func NewFBLReportRepo(db *pgxpool.Pool) *FBLReportRepo {
	return &FBLReportRepo{db: db}
}

// Create records a new FBL complaint.
func (r *FBLReportRepo) Create(ctx context.Context, report *FBLReport) (string, error) {
	id := types.NewUUIDv7()

	var detailsJSON []byte
	if report.Details != nil {
		detailsJSON = report.Details
	}

	_, err := r.db.Exec(ctx,
		`INSERT INTO fbl_reports (id, domain_id, mailbox_id, original_message_id, reporter_domain, complaint_type, feedback_id, details, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())`,
		id, report.DomainID, report.MailboxID, report.OriginalMessageID,
		report.ReporterDomain, report.ComplaintType, report.FeedbackID, detailsJSON,
	)
	if err != nil {
		return "", fmt.Errorf("insert fbl report: %w", err)
	}
	return id, nil
}

// ListByDomain returns FBL reports for a domain.
func (r *FBLReportRepo) ListByDomain(ctx context.Context, domainID string, limit int) ([]FBLReport, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(ctx,
		`SELECT id, domain_id, mailbox_id, original_message_id, reporter_domain, complaint_type, feedback_id, details, created_at
		 FROM fbl_reports WHERE domain_id = $1 ORDER BY created_at DESC LIMIT $2`, domainID, limit)
	if err != nil {
		return nil, fmt.Errorf("list fbl reports: %w", err)
	}
	defer rows.Close()
	return scanFBLReports(rows)
}

// ListRecent returns recent FBL reports across all domains.
func (r *FBLReportRepo) ListRecent(ctx context.Context, limit int) ([]FBLReport, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(ctx,
		`SELECT id, domain_id, mailbox_id, original_message_id, reporter_domain, complaint_type, feedback_id, details, created_at
		 FROM fbl_reports ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list recent fbl reports: %w", err)
	}
	defer rows.Close()
	return scanFBLReports(rows)
}

// CountByDomain returns the number of complaints for a domain in a time range.
func (r *FBLReportRepo) CountByDomain(ctx context.Context, domainID string, from, to time.Time) (int, error) {
	var count int
	err := r.db.QueryRow(ctx,
		`SELECT COUNT(*) FROM fbl_reports WHERE domain_id = $1 AND created_at >= $2 AND created_at < $3`,
		domainID, from, to,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count fbl reports: %w", err)
	}
	return count, nil
}

func scanFBLReports(rows interface{ Next() bool; Scan(dest ...any) error }) ([]FBLReport, error) {
	var reports []FBLReport
	for rows.Next() {
		var r FBLReport
		if err := rows.Scan(&r.ID, &r.DomainID, &r.MailboxID, &r.OriginalMessageID,
			&r.ReporterDomain, &r.ComplaintType, &r.FeedbackID, &r.Details, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan fbl report: %w", err)
		}
		reports = append(reports, r)
	}
	return reports, nil
}
