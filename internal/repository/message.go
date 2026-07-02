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

// GetByMessageID retrieves a message by its RFC 5322 Message-ID. message_id is
// not unique (an inbound copy and our outbound original can share one, and the
// value is attacker-controllable on inbound), so the result is pinned to the
// most recent row for determinism (audit P2-6) rather than an arbitrary one.
func (r *MessageRepo) GetByMessageID(ctx context.Context, messageID string) (*Message, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, domain_id, mailbox_id, message_id, direction, sender, recipients, subject, size_bytes, status, spam_score, spam_action, queue_id, headers, created_at
		 FROM messages WHERE message_id = $1 ORDER BY created_at DESC LIMIT 1`, messageID)

	var m Message
	if err := scanMessage(row, &m); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get message by message_id: %w", err)
	}
	return &m, nil
}

// GetOutboundByMessageID retrieves the most recent OUTBOUND message with the
// given Message-ID. Used for ARF/FBL attribution (audit D-M3/P2-6): a complaint
// may only be attributed to a message we actually sent, and message_id can
// collide with an inbound copy, so the query filters on direction and pins to
// the newest row for a deterministic answer.
func (r *MessageRepo) GetOutboundByMessageID(ctx context.Context, messageID string) (*Message, error) {
	row := r.db.QueryRow(ctx,
		`SELECT id, domain_id, mailbox_id, message_id, direction, sender, recipients, subject, size_bytes, status, spam_score, spam_action, queue_id, headers, created_at
		 FROM messages WHERE message_id = $1 AND direction = 'outbound' ORDER BY created_at DESC LIMIT 1`, messageID)

	var m Message
	if err := scanMessage(row, &m); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, fmt.Errorf("get outbound message by message_id: %w", err)
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

// ListBySubject returns message metadata belonging to a single data subject:
// messages they sent (sender), messages they received (the subject is in
// recipients), and any row still linked to their mailbox (mailbox_id). The
// recipients match is essential: inbound mail is stored with mailbox_id NULL
// and the recipient only in recipients (see handle_inbound.go), so a
// mailbox_id/sender-only filter would miss every received message. Used by the
// DSAR exporter; ordered oldest-first for a stable export.
func (r *MessageRepo) ListBySubject(ctx context.Context, mailboxID, email string) ([]Message, error) {
	rows, err := r.db.Query(ctx,
		`SELECT id, domain_id, mailbox_id, message_id, direction, sender, recipients, subject, size_bytes, status, spam_score, spam_action, queue_id, headers, created_at
		 FROM messages WHERE ($1 <> '' AND mailbox_id = $1::uuid)
		    OR LOWER(sender) = LOWER($2)
		    OR EXISTS (SELECT 1 FROM unnest(recipients) AS rcpt WHERE LOWER(rcpt) = LOWER($2))
		 ORDER BY created_at ASC`, mailboxID, email)
	if err != nil {
		return nil, fmt.Errorf("list messages by subject: %w", err)
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

// DeleteBySubject removes message metadata belonging to a single data subject:
// messages they sent (sender), messages they received (subject in recipients),
// and any row still linked to their mailbox (mailbox_id). The recipients match
// is essential — inbound mail is stored with mailbox_id NULL and the recipient
// only in recipients (handle_inbound.go), so a mailbox_id/sender-only filter
// would leave every received message behind on erasure. Used by DSAR erasure.
//
// mailboxID may be "" (e.g. the reconciler after a restore that brought back
// message rows but not the mailbox): the guard skips the uuid branch so the
// empty string is never cast to uuid, and matching falls back to sender +
// recipients. The mailbox_id branch is largely belt-and-suspenders today
// (outbound rows that carry it) since the sender/recipients clauses already
// cover both directions regardless of the mailbox link. Returns the count.
//
// The sender/recipients match is case-insensitive (audit G-M1): mail is stored
// with the verbatim envelope address, so a message to John.Doe@corp.example must
// still be erased when the DSAR names the canonical john.doe@corp.example, or
// mixed-case mail survives an Art.17 erasure. LOWER() on both sides also matches
// already-stored mixed-case rows, so no data migration is required.
func (r *MessageRepo) DeleteBySubject(ctx context.Context, mailboxID, email string) (int64, error) {
	tag, err := r.db.Exec(ctx,
		`DELETE FROM messages WHERE ($1 <> '' AND mailbox_id = $1::uuid)
		    OR LOWER(sender) = LOWER($2)
		    OR EXISTS (SELECT 1 FROM unnest(recipients) AS rcpt WHERE LOWER(rcpt) = LOWER($2))`,
		mailboxID, email)
	if err != nil {
		return 0, fmt.Errorf("delete messages by subject: %w", err)
	}
	return tag.RowsAffected(), nil
}

func scanMessage(row pgx.Row, m *Message) error {
	return row.Scan(&m.ID, &m.DomainID, &m.MailboxID, &m.MessageID, &m.Direction,
		&m.Sender, &m.Recipients, &m.Subject, &m.SizeBytes, &m.Status,
		&m.SpamScore, &m.SpamAction, &m.QueueID, &m.Headers, &m.CreatedAt)
}
