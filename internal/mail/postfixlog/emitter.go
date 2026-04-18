package postfixlog

import (
	"context"
	"log/slog"
	"time"

	"github.com/Veltara-Works/vectis/internal/mail"
	vectismetrics "github.com/Veltara-Works/vectis/internal/metrics"
	"github.com/Veltara-Works/vectis/internal/repository"
)

// MessageLookup is the subset of repository.MessageRepo the emitter needs.
// Defined as an interface so tests can substitute a fake.
type MessageLookup interface {
	GetByMessageID(ctx context.Context, messageID string) (*repository.Message, error)
	UpdateStatus(ctx context.Context, id, status string) error
}

// WebhookDispatch is the subset of mail.WebhookDispatcher the emitter needs.
type WebhookDispatch interface {
	Dispatch(ctx context.Context, domainID string, event mail.WebhookEvent)
}

// StatsIncrementer is the subset of repository.MailStatsRepo the emitter needs.
// Nil is tolerated — stats are best-effort.
type StatsIncrementer interface {
	Increment(ctx context.Context, domainID, event string, bytes int) error
}

// NewWebhookEmitter returns a Handler that looks up the Message-ID in the
// messages table, updates its status, and fires the corresponding webhook
// event. Events with no resolvable Message-ID or no matching row are dropped
// (they represent mail Vectis didn't originate, e.g. DSNs generated locally).
func NewWebhookEmitter(
	messages MessageLookup,
	dispatcher WebhookDispatch,
	stats StatsIncrementer,
	logger *slog.Logger,
) Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(ctx context.Context, ev Event) {
		if ev.MessageID == "" {
			// No cleanup line seen for this queue_id — either the tailer
			// started mid-run or the mail did not originate from /send.
			return
		}

		// Lookup in DB; use a fresh context so a cancelled tailer ctx
		// doesn't abort the DB call mid-flight.
		dbCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		msg, err := messages.GetByMessageID(dbCtx, ev.MessageID)
		if err != nil {
			logger.Error("postfix log emitter: message lookup failed",
				"error", err, "message_id", ev.MessageID, "queue_id", ev.QueueID)
			return
		}
		if msg == nil {
			// Not one of our outbound messages — skip silently.
			return
		}
		if msg.Direction != "outbound" {
			// Inbound message delivered via LMTP hit this path via the smtp
			// component; ignore — inbound webhooks already fire from the
			// /internal/inbound handler.
			return
		}

		var eventName string
		var newStatus string
		switch ev.Type {
		case EventDelivered:
			eventName = "mail.delivered"
			newStatus = "delivered"
			vectismetrics.EmailsDelivered.Inc()
		case EventBounced:
			eventName = "mail.bounced"
			newStatus = "bounced"
			vectismetrics.EmailsBounced.Inc()
		default:
			// Deferred: update status but do not fire a webhook event yet.
			// A deferred message will eventually resolve to sent or bounced.
			if err := messages.UpdateStatus(dbCtx, msg.ID, "queued"); err != nil {
				logger.Debug("postfix log emitter: deferred status update failed",
					"error", err, "message_id", ev.MessageID)
			}
			return
		}

		if err := messages.UpdateStatus(dbCtx, msg.ID, newStatus); err != nil {
			logger.Error("postfix log emitter: status update failed",
				"error", err, "message_id", ev.MessageID, "new_status", newStatus)
		}

		if stats != nil && ev.Type == EventBounced {
			_ = stats.Increment(dbCtx, msg.DomainID, "bounced", 0)
		}

		dispatcher.Dispatch(dbCtx, msg.DomainID, mail.WebhookEvent{
			ID:        ev.MessageID,
			Event:     eventName,
			Timestamp: ev.Timestamp.Format(time.RFC3339),
			Data: map[string]any{
				"message_id": ev.MessageID,
				"queue_id":   ev.QueueID,
				"recipient":  ev.Recipient,
				"relay":      ev.Relay,
				"dsn":        ev.DSN,
				"delay":      ev.Delay,
				"response":   ev.Response,
				"status":     ev.Status,
			},
		})
	}
}
