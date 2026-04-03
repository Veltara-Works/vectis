package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// MailStats represents hourly aggregated mail statistics for a domain.
type MailStats struct {
	ID             string    `json:"id"`
	DomainID       string    `json:"domain_id"`
	Hour           time.Time `json:"hour"`
	Sent           int       `json:"sent"`
	Received       int       `json:"received"`
	Bounced        int       `json:"bounced"`
	Spam           int       `json:"spam"`
	Failed         int       `json:"failed"`
	SizeBytesTotal int64     `json:"size_bytes_total"`
}

// DomainStatsAggregate holds aggregated stats for a domain over a time range.
type DomainStatsAggregate struct {
	DomainID   string `json:"domain_id"`
	DomainName string `json:"domain_name,omitempty"`
	Sent       int    `json:"sent"`
	Received   int    `json:"received"`
	Bounced    int    `json:"bounced"`
	Spam       int    `json:"spam"`
	Failed     int    `json:"failed"`
	SizeBytes  int64  `json:"size_bytes_total"`
}

// MailStatsRepo handles mail statistics storage and retrieval.
type MailStatsRepo struct {
	db *pgxpool.Pool
}

// NewMailStatsRepo creates a new mail statistics repository.
func NewMailStatsRepo(db *pgxpool.Pool) *MailStatsRepo {
	return &MailStatsRepo{db: db}
}

// Increment atomically increments a stat counter for the given domain and current hour.
// Uses INSERT ... ON CONFLICT to upsert.
func (r *MailStatsRepo) Increment(ctx context.Context, domainID string, field string, sizeBytes int) error {
	hour := time.Now().UTC().Truncate(time.Hour)
	id := types.NewUUIDv7()

	var setClause string
	switch field {
	case "sent":
		setClause = "sent = mail_stats.sent + 1"
	case "received":
		setClause = "received = mail_stats.received + 1"
	case "bounced":
		setClause = "bounced = mail_stats.bounced + 1"
	case "spam":
		setClause = "spam = mail_stats.spam + 1"
	case "failed":
		setClause = "failed = mail_stats.failed + 1"
	default:
		return fmt.Errorf("unknown stats field: %s", field)
	}

	if sizeBytes > 0 {
		setClause += fmt.Sprintf(", size_bytes_total = mail_stats.size_bytes_total + %d", sizeBytes)
	}

	_, err := r.db.Exec(ctx,
		fmt.Sprintf(`INSERT INTO mail_stats (id, domain_id, hour, %s, size_bytes_total)
		 VALUES ($1, $2, $3, 1, $4)
		 ON CONFLICT (domain_id, hour) DO UPDATE SET %s`, field, setClause),
		id, domainID, hour, sizeBytes,
	)
	if err != nil {
		return fmt.Errorf("increment mail stats: %w", err)
	}
	return nil
}

// GetHourly returns hourly stats for a domain over a time range.
func (r *MailStatsRepo) GetHourly(ctx context.Context, domainID string, from, to time.Time) ([]MailStats, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, domain_id, hour, sent, received, bounced, spam, failed, size_bytes_total
		 FROM mail_stats
		 WHERE domain_id = $1 AND hour >= $2 AND hour < $3
		 ORDER BY hour ASC`, domainID, from, to)
	if err != nil {
		return nil, fmt.Errorf("get hourly stats: %w", err)
	}
	defer rows.Close()

	var stats []MailStats
	for rows.Next() {
		var s MailStats
		if err := rows.Scan(&s.ID, &s.DomainID, &s.Hour, &s.Sent, &s.Received, &s.Bounced, &s.Spam, &s.Failed, &s.SizeBytesTotal); err != nil {
			return nil, fmt.Errorf("scan mail stats: %w", err)
		}
		stats = append(stats, s)
	}
	return stats, nil
}

// GetDailyAggregate returns daily aggregated stats for a domain.
func (r *MailStatsRepo) GetDailyAggregate(ctx context.Context, domainID string, from, to time.Time) ([]MailStats, error) {
	rows, err := r.db.Query(ctx,
		`SELECT domain_id, date_trunc('day', hour) AS day,
		        SUM(sent)::int, SUM(received)::int, SUM(bounced)::int, SUM(spam)::int, SUM(failed)::int, SUM(size_bytes_total)
		 FROM mail_stats
		 WHERE domain_id = $1 AND hour >= $2 AND hour < $3
		 GROUP BY domain_id, day
		 ORDER BY day ASC`, domainID, from, to)
	if err != nil {
		return nil, fmt.Errorf("get daily aggregate: %w", err)
	}
	defer rows.Close()

	var stats []MailStats
	for rows.Next() {
		var s MailStats
		if err := rows.Scan(&s.DomainID, &s.Hour, &s.Sent, &s.Received, &s.Bounced, &s.Spam, &s.Failed, &s.SizeBytesTotal); err != nil {
			return nil, fmt.Errorf("scan daily aggregate: %w", err)
		}
		stats = append(stats, s)
	}
	return stats, nil
}

// GetAllDomainsAggregate returns aggregated stats across all (or specified) domains.
func (r *MailStatsRepo) GetAllDomainsAggregate(ctx context.Context, domainIDs []string, from, to time.Time) ([]DomainStatsAggregate, error) {
	var query string
	var args []any

	if len(domainIDs) > 0 {
		query = `SELECT ms.domain_id, d.name,
		                SUM(ms.sent)::int, SUM(ms.received)::int, SUM(ms.bounced)::int, SUM(ms.spam)::int, SUM(ms.failed)::int, SUM(ms.size_bytes_total)
		         FROM mail_stats ms JOIN domains d ON d.id = ms.domain_id
		         WHERE ms.domain_id = ANY($1) AND ms.hour >= $2 AND ms.hour < $3
		         GROUP BY ms.domain_id, d.name
		         ORDER BY SUM(ms.sent) + SUM(ms.received) DESC`
		args = []any{domainIDs, from, to}
	} else {
		query = `SELECT ms.domain_id, d.name,
		                SUM(ms.sent)::int, SUM(ms.received)::int, SUM(ms.bounced)::int, SUM(ms.spam)::int, SUM(ms.failed)::int, SUM(ms.size_bytes_total)
		         FROM mail_stats ms JOIN domains d ON d.id = ms.domain_id
		         WHERE ms.hour >= $1 AND ms.hour < $2
		         GROUP BY ms.domain_id, d.name
		         ORDER BY SUM(ms.sent) + SUM(ms.received) DESC`
		args = []any{from, to}
	}

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("get all domains aggregate: %w", err)
	}
	defer rows.Close()

	var agg []DomainStatsAggregate
	for rows.Next() {
		var a DomainStatsAggregate
		if err := rows.Scan(&a.DomainID, &a.DomainName, &a.Sent, &a.Received, &a.Bounced, &a.Spam, &a.Failed, &a.SizeBytes); err != nil {
			return nil, fmt.Errorf("scan domain aggregate: %w", err)
		}
		agg = append(agg, a)
	}
	return agg, nil
}
