package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// Webhook represents a configured webhook endpoint.
type Webhook struct {
	ID        string     `json:"id"`
	DomainID  *string    `json:"domain_id,omitempty"` // NULL = global
	URL       string     `json:"url"`
	Secret    string     `json:"-"`                   // never expose in API responses
	Events    []string   `json:"events"`
	Active    bool       `json:"active"`
	CreatedBy string     `json:"created_by"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// WebhookCreate holds fields for creating a webhook.
type WebhookCreate struct {
	DomainID  *string
	URL       string
	Secret    string
	Events    []string
	CreatedBy string
}

// WebhookDelivery represents a single webhook delivery attempt.
type WebhookDelivery struct {
	ID          string     `json:"id"`
	WebhookID   string     `json:"webhook_id"`
	EventType   string     `json:"event_type"`
	Payload     []byte     `json:"payload"`
	StatusCode  *int       `json:"status_code,omitempty"`
	Response    *string    `json:"response,omitempty"`
	Attempt     int        `json:"attempt"`
	NextRetry   *time.Time `json:"next_retry,omitempty"`
	DeliveredAt *time.Time `json:"delivered_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

// WebhookRepo handles webhook CRUD and delivery logging.
type WebhookRepo struct {
	db *pgxpool.Pool
}

// NewWebhookRepo creates a new webhook repository.
func NewWebhookRepo(db *pgxpool.Pool) *WebhookRepo {
	return &WebhookRepo{db: db}
}

// --- Webhook CRUD ---

// Create inserts a new webhook.
func (r *WebhookRepo) Create(ctx context.Context, input WebhookCreate) (*Webhook, error) {
	id := types.NewUUIDv7()
	_, err := r.db.Exec(ctx,
		`INSERT INTO webhooks (id, domain_id, url, secret, events, active, created_by, created_at, updated_at)
		 VALUES ($1, $2, $3, $4, $5, true, $6, NOW(), NOW())`,
		id, input.DomainID, input.URL, input.Secret, input.Events, input.CreatedBy,
	)
	if err != nil {
		return nil, fmt.Errorf("insert webhook: %w", err)
	}
	return r.GetByID(ctx, id)
}

// GetByID fetches a webhook by ID.
func (r *WebhookRepo) GetByID(ctx context.Context, id string) (*Webhook, error) {
	w := &Webhook{}
	err := r.db.QueryRow(ctx,
		`SELECT id, domain_id, url, secret, events, active, created_by, created_at, updated_at
		 FROM webhooks WHERE id = $1`, id,
	).Scan(&w.ID, &w.DomainID, &w.URL, &w.Secret, &w.Events, &w.Active, &w.CreatedBy, &w.CreatedAt, &w.UpdatedAt)
	if err == pgx.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get webhook: %w", err)
	}
	return w, nil
}

// ListByDomain returns webhooks for a domain (including global webhooks).
func (r *WebhookRepo) ListByDomain(ctx context.Context, domainID string) ([]Webhook, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, domain_id, url, secret, events, active, created_by, created_at, updated_at
		 FROM webhooks WHERE (domain_id = $1 OR domain_id IS NULL) AND active = true
		 ORDER BY created_at`, domainID)
	if err != nil {
		return nil, fmt.Errorf("list webhooks by domain: %w", err)
	}
	defer rows.Close()
	return scanWebhooks(rows)
}

// ListAll returns all webhooks.
func (r *WebhookRepo) ListAll(ctx context.Context) ([]Webhook, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, domain_id, url, secret, events, active, created_by, created_at, updated_at
		 FROM webhooks ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("list all webhooks: %w", err)
	}
	defer rows.Close()
	return scanWebhooks(rows)
}

// Delete removes a webhook.
func (r *WebhookRepo) Delete(ctx context.Context, id string) (bool, error) {
	result, err := r.db.Exec(ctx, `DELETE FROM webhooks WHERE id = $1`, id)
	if err != nil {
		return false, fmt.Errorf("delete webhook: %w", err)
	}
	return result.RowsAffected() > 0, nil
}

// --- Delivery log ---

// CreateDelivery inserts a pending webhook delivery.
func (r *WebhookRepo) CreateDelivery(ctx context.Context, webhookID, eventType string, payload []byte) (string, error) {
	id := types.NewUUIDv7()
	now := time.Now().UTC()
	_, err := r.db.Exec(ctx,
		`INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, attempt, next_retry, created_at)
		 VALUES ($1, $2, $3, $4, 1, $5, $5)`,
		id, webhookID, eventType, payload, now,
	)
	if err != nil {
		return "", fmt.Errorf("insert webhook delivery: %w", err)
	}
	return id, nil
}

// MarkDelivered updates a delivery as successfully delivered.
func (r *WebhookRepo) MarkDelivered(ctx context.Context, id string, statusCode int, response string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE webhook_deliveries SET status_code = $1, response = $2, delivered_at = NOW(), next_retry = NULL WHERE id = $3`,
		statusCode, truncate(response, 1024), id,
	)
	if err != nil {
		return fmt.Errorf("mark delivered: %w", err)
	}
	return nil
}

// MarkFailed updates a delivery with the failure info and schedules a retry.
func (r *WebhookRepo) MarkFailed(ctx context.Context, id string, statusCode int, response string, nextRetry *time.Time) error {
	_, err := r.db.Exec(ctx,
		`UPDATE webhook_deliveries SET status_code = $1, response = $2, attempt = attempt + 1, next_retry = $3 WHERE id = $4`,
		statusCode, truncate(response, 1024), nextRetry, id,
	)
	if err != nil {
		return fmt.Errorf("mark failed: %w", err)
	}
	return nil
}

// ListPendingRetries returns deliveries due for retry.
func (r *WebhookRepo) ListPendingRetries(ctx context.Context, limit int) ([]WebhookDelivery, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := r.db.Query(ctx,
		`SELECT d.id, d.webhook_id, d.event_type, d.payload, d.status_code, d.response, d.attempt, d.next_retry, d.delivered_at, d.created_at
		 FROM webhook_deliveries d
		 JOIN webhooks w ON d.webhook_id = w.id
		 WHERE d.delivered_at IS NULL AND d.next_retry IS NOT NULL AND d.next_retry <= NOW() AND w.active = true
		 ORDER BY d.next_retry LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("list pending retries: %w", err)
	}
	defer rows.Close()

	var deliveries []WebhookDelivery
	for rows.Next() {
		var d WebhookDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventType, &d.Payload, &d.StatusCode, &d.Response, &d.Attempt, &d.NextRetry, &d.DeliveredAt, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan delivery: %w", err)
		}
		deliveries = append(deliveries, d)
	}
	return deliveries, nil
}

func scanWebhooks(rows interface{ Next() bool; Scan(dest ...any) error }) ([]Webhook, error) {
	var webhooks []Webhook
	for rows.Next() {
		var w Webhook
		if err := rows.Scan(&w.ID, &w.DomainID, &w.URL, &w.Secret, &w.Events, &w.Active, &w.CreatedBy, &w.CreatedAt, &w.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		webhooks = append(webhooks, w)
	}
	return webhooks, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
