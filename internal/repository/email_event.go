package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// EmailEvent represents a single engagement tracking event (open or click).
type EmailEvent struct {
	ID        string    `json:"id"`
	DomainID  string    `json:"domain_id"`
	MessageID string    `json:"message_id"`
	EventType string    `json:"event_type"` // "open" or "click"
	TargetURL *string   `json:"target_url,omitempty"`
	UserAgent *string   `json:"user_agent,omitempty"`
	IPAddress *string   `json:"ip_address,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// MessageEngagement aggregates open/click counts for a single message.
type MessageEngagement struct {
	MessageID    string     `json:"message_id"`
	Opens        int        `json:"opens"`
	UniqueOpens  int        `json:"unique_opens"`
	Clicks       int        `json:"clicks"`
	UniqueClicks int        `json:"unique_clicks"`
	FirstOpenAt  *time.Time `json:"first_open_at,omitempty"`
	LastOpenAt   *time.Time `json:"last_open_at,omitempty"`
	FirstClickAt *time.Time `json:"first_click_at,omitempty"`
	LastClickAt  *time.Time `json:"last_click_at,omitempty"`
}

// DomainEngagement aggregates open/click counts for a domain over a time range.
type DomainEngagement struct {
	DomainID        string `json:"domain_id"`
	Opens           int    `json:"opens"`
	Clicks          int    `json:"clicks"`
	MessagesOpened  int    `json:"messages_opened"`
	MessagesClicked int    `json:"messages_clicked"`
}

// EmailEventRepo handles engagement tracking event storage and queries.
type EmailEventRepo struct {
	db *pgxpool.Pool
}

// NewEmailEventRepo creates a new engagement event repository.
func NewEmailEventRepo(db *pgxpool.Pool) *EmailEventRepo {
	return &EmailEventRepo{db: db}
}

// Create records a new engagement event.
func (r *EmailEventRepo) Create(ctx context.Context, ev *EmailEvent) error {
	if ev.ID == "" {
		ev.ID = types.NewUUIDv7()
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	_, err := r.db.Exec(ctx,
		`INSERT INTO email_events (id, domain_id, message_id, event_type, target_url, user_agent, ip_address, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7::inet, $8)`,
		ev.ID, ev.DomainID, ev.MessageID, ev.EventType,
		ev.TargetURL, ev.UserAgent, ev.IPAddress, ev.CreatedAt)
	if err != nil {
		return fmt.Errorf("insert email_event: %w", err)
	}
	return nil
}

// GetMessageEngagement returns aggregate counts for a single message (by RFC 5322 Message-ID).
func (r *EmailEventRepo) GetMessageEngagement(ctx context.Context, messageID string) (*MessageEngagement, error) {
	row := r.db.QueryRow(ctx,
		`SELECT
		   COUNT(*) FILTER (WHERE event_type = 'open')   AS opens,
		   COUNT(DISTINCT ip_address) FILTER (WHERE event_type = 'open')  AS unique_opens,
		   COUNT(*) FILTER (WHERE event_type = 'click')  AS clicks,
		   COUNT(DISTINCT ip_address) FILTER (WHERE event_type = 'click') AS unique_clicks,
		   MIN(created_at) FILTER (WHERE event_type = 'open')  AS first_open,
		   MAX(created_at) FILTER (WHERE event_type = 'open')  AS last_open,
		   MIN(created_at) FILTER (WHERE event_type = 'click') AS first_click,
		   MAX(created_at) FILTER (WHERE event_type = 'click') AS last_click
		 FROM email_events WHERE message_id = $1`, messageID)

	e := &MessageEngagement{MessageID: messageID}
	if err := row.Scan(&e.Opens, &e.UniqueOpens, &e.Clicks, &e.UniqueClicks,
		&e.FirstOpenAt, &e.LastOpenAt, &e.FirstClickAt, &e.LastClickAt); err != nil {
		return nil, fmt.Errorf("aggregate message engagement: %w", err)
	}
	return e, nil
}

// GetDomainEngagement returns aggregate counts for a domain over [since, until].
// If until is zero, it defaults to now.
func (r *EmailEventRepo) GetDomainEngagement(ctx context.Context, domainID string, since, until time.Time) (*DomainEngagement, error) {
	if until.IsZero() {
		until = time.Now().UTC()
	}
	row := r.db.QueryRow(ctx,
		`SELECT
		   COUNT(*) FILTER (WHERE event_type = 'open')  AS opens,
		   COUNT(*) FILTER (WHERE event_type = 'click') AS clicks,
		   COUNT(DISTINCT message_id) FILTER (WHERE event_type = 'open')  AS msgs_opened,
		   COUNT(DISTINCT message_id) FILTER (WHERE event_type = 'click') AS msgs_clicked
		 FROM email_events
		 WHERE domain_id = $1 AND created_at >= $2 AND created_at <= $3`,
		domainID, since, until)

	e := &DomainEngagement{DomainID: domainID}
	if err := row.Scan(&e.Opens, &e.Clicks, &e.MessagesOpened, &e.MessagesClicked); err != nil {
		return nil, fmt.Errorf("aggregate domain engagement: %w", err)
	}
	return e, nil
}

// ListByMessage returns all events for a given message, newest first.
func (r *EmailEventRepo) ListByMessage(ctx context.Context, messageID string, limit int) ([]EmailEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := r.db.Query(ctx,
		`SELECT id, domain_id, message_id, event_type, target_url, user_agent, host(ip_address), created_at
		 FROM email_events WHERE message_id = $1
		 ORDER BY created_at DESC LIMIT $2`, messageID, limit)
	if err != nil {
		return nil, fmt.Errorf("list message events: %w", err)
	}
	defer rows.Close()

	var events []EmailEvent
	for rows.Next() {
		var ev EmailEvent
		if err := rows.Scan(&ev.ID, &ev.DomainID, &ev.MessageID, &ev.EventType,
			&ev.TargetURL, &ev.UserAgent, &ev.IPAddress, &ev.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan email_event: %w", err)
		}
		events = append(events, ev)
	}
	return events, nil
}
