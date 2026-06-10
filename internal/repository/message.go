package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/Veltara-Works/vectis/internal/types"
)

// Message represents stored message metadata.
type Message struct {
	ID         string          `json:"id"`
	DomainID   string          `json:"domain_id"`
	MailboxID  *string         `json:"mailbox_id,omitempty"`
	MessageID  string          `json:"message_id"`
	Direction  string          `json:"direction"` // "inbound" or "outbound"
	Sender     string          `json:"sender"`
	Recipients []string        `json:"recipients"`
	Subject    string          `json:"subject,omitempty"`
	SizeBytes  int             `json:"size_bytes"`
	Status     string          `json:"status"` // queued, sent, delivered, bounced, failed, spam
	SpamScore  *float64        `json:"spam_score,omitempty"`
	SpamAction *string         `json:"spam_action,omitempty"`
	QueueID    *string         `json:"queue_id,omitempty"`
	Headers    json.RawMessage `json:"headers,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
}

// MessageFilter holds filters for listing/searching messages.
type MessageFilter struct {
	DomainID  string
	Direction string // "inbound", "outbound", or "" for both
	Status    string
	Search    string // full-text search on subject + sender
	Sender    string
}

// MessageRepo handles message metadata storage and retrieval.
type MessageRepo struct {
	db *pgxpool.Pool
}

// NewMessageRepo creates a new message repository.
func NewMessageRepo(db *pgxpool.Pool) *MessageRepo {
	return &MessageRepo{db: db}
}

// Create stores a new message metadata record.
func (r *MessageRepo) Create(ctx context.Context, msg *Message) error {
	if msg.ID == "" {
		msg.ID = types.NewUUIDv7()
	}

	_, err := r.db.Exec(ctx,
		`INSERT INTO messages (id, domain_id, mailbox_id, message_id, direction, sender, recipients, subject, size_bytes, status, spam_score, spam_action, queue_id, headers, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)`,
		msg.ID, msg.DomainID, msg.MailboxID, msg.MessageID, msg.Direction, msg.Sender,
		msg.Recipients, msg.Subject, msg.SizeBytes, msg.Status,
		msg.SpamScore, msg.SpamAction, msg.QueueID, msg.Headers,
		msg.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert message: %w", err)
	}
	return nil
}

// GetByID retrieves a single message by its UUID.
func (r *MessageRepo) GetByID(ctx context.Context, id string) (*Message, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, domain_id, mailbox_id, message_id, direction, sender, recipients, subject, size_bytes, status, spam_score, spam_action, queue_id, headers, created_at
		 FROM messages WHERE id = $1`, id)

	var m Message
	if err := scanMessage(row, &m); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get message: %w", err)
	}
	return &m, nil
}

// GetByMessageID retrieves a message by its RFC 5322 Message-ID.
func (r *MessageRepo) GetByMessageID(ctx context.Context, messageID string) (*Message, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, domain_id, mailbox_id, message_id, direction, sender, recipients, subject, size_bytes, status, spam_score, spam_action, queue_id, headers, created_at
		 FROM messages WHERE message_id = $1`, messageID)

	var m Message
	if err := scanMessage(row, &m); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get message by message_id: %w", err)
	}
	return &m, nil
}

// List retrieves messages with filtering and pagination.
func (r *MessageRepo) List(ctx context.Context, filter MessageFilter, p PaginationParams) ([]Message, error) {
	var args []any
	var conditions []string
	argIdx := 1

	if filter.DomainID != "" {
		conditions = append(conditions, fmt.Sprintf("domain_id = $%d", argIdx))
		args = append(args, filter.DomainID)
		argIdx++
	}
	if filter.Direction != "" {
		conditions = append(conditions, fmt.Sprintf("direction = $%d", argIdx))
		args = append(args, filter.Direction)
		argIdx++
	}
	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", argIdx))
		args = append(args, filter.Status)
		argIdx++
	}
	if filter.Sender != "" {
		conditions = append(conditions, fmt.Sprintf("sender = $%d", argIdx))
		args = append(args, filter.Sender)
		argIdx++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"to_tsvector('english', coalesce(subject, '') || ' ' || sender) @@ plainto_tsquery('english', $%d)", argIdx))
		args = append(args, filter.Search)
		argIdx++
	}

	if p.Cursor != nil {
		conditions = append(conditions, fmt.Sprintf("created_at < $%d", argIdx))
		args = append(args, *p.Cursor)
		argIdx++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	limit := p.Limit
	if limit <= 0 {
		limit = 50
	}

	query := fmt.Sprintf(
		`SELECT id, domain_id, mailbox_id, message_id, direction, sender, recipients, subject, size_bytes, status, spam_score, spam_action, queue_id, headers, created_at
		 FROM messages %s ORDER BY created_at DESC LIMIT %d`, where, limit+1)

	rows, err := r.db.Query(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list messages: %w", err)
	}
	defer rows.Close()

	var messages []Message
	for rows.Next() {
		var m Message
		if err := rows.Scan(&m.ID, &m.DomainID, &m.MailboxID, &m.MessageID, &m.Direction,
			&m.Sender, &m.Recipients, &m.Subject, &m.SizeBytes, &m.Status,
			&m.SpamScore, &m.SpamAction, &m.QueueID, &m.Headers, &m.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan message: %w", err)
		}
		messages = append(messages, m)
	}
	return messages, nil
}

// UpdateStatus updates the status of a message (e.g. queued → sent).
func (r *MessageRepo) UpdateStatus(ctx context.Context, id, status string) error {
	_, err := r.db.Exec(ctx,
		`UPDATE messages SET status = $1 WHERE id = $2`, status, id)
	if err != nil {
		return fmt.Errorf("update message status: %w", err)
	}
	return nil
}

// DeleteOlderThan removes message metadata rows created before the given time
// and returns the number deleted. Used by the retention sweeper. This purges
// only the metadata index (sender/recipients/subject/headers); it does not
// touch the on-disk mail store, which Dovecot owns.
func (r *MessageRepo) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM messages WHERE created_at < $1`, before)
	if err != nil {
		return 0, fmt.Errorf("delete old messages: %w", err)
	}
	return tag.RowsAffected(), nil
}

func scanMessage(row pgx.Row, m *Message) error {
	return row.Scan(&m.ID, &m.DomainID, &m.MailboxID, &m.MessageID, &m.Direction,
		&m.Sender, &m.Recipients, &m.Subject, &m.SizeBytes, &m.Status,
		&m.SpamScore, &m.SpamAction, &m.QueueID, &m.Headers, &m.CreatedAt)
}
