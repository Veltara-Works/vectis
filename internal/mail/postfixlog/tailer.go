// Package postfixlog tails the Postfix mail log and emits structured
// delivery events (sent / bounced / deferred) so the API can dispatch
// mail.delivered and mail.bounced webhooks.
//
// Postfix log lines we care about (examples):
//
//   postfix/cleanup[1234]: ABCDEF12: message-id=<abc123@mail.example.com>
//   postfix/smtp[5678]: ABCDEF12: to=<u@ex.com>, relay=mx.ex.com[1.2.3.4]:25, delay=0.5, delays=0.1/0/0.2/0.2, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 123456)
//   postfix/smtp[5678]: ABCDEF12: to=<u@ex.com>, relay=mx.ex.com[1.2.3.4]:25, delay=1.0, delays=..., dsn=5.1.1, status=bounced (host ... said: 550 5.1.1 <u@ex.com>: User unknown)
//
// The tailer maintains an in-memory LRU of queue_id → message_id so that a
// later `status=sent|bounced` line can be resolved back to the Message-ID we
// stored when we accepted the send. On resolution the tailer calls a supplied
// callback; the caller is responsible for looking up the message in the DB
// and dispatching the webhook.
package postfixlog

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// EventType identifies the kind of delivery event.
type EventType string

const (
	EventDelivered EventType = "delivered"
	EventBounced   EventType = "bounced"
	EventDeferred  EventType = "deferred"
)

// Event is the structured result of parsing a Postfix log line.
type Event struct {
	Type      EventType
	QueueID   string    // Postfix queue id, e.g. "ABCDEF12"
	MessageID string    // RFC 5322 Message-ID (no angle brackets); empty if unresolved
	Recipient string    // envelope recipient from `to=<...>`
	Relay     string    // remote relay, e.g. "mx.example.com[1.2.3.4]:25"
	DSN       string    // DSN status code, e.g. "2.0.0"
	Status    string    // raw status token, e.g. "sent", "bounced", "deferred"
	Response  string    // remote SMTP response tail, inside parentheses
	Delay     float64   // seconds from enqueue to delivery attempt
	Timestamp time.Time // wall-clock time of the event (ingest time)
}

// Handler is invoked for every resolved delivery event. Implementations
// must be safe to call concurrently and should not block the tailer.
type Handler func(ctx context.Context, ev Event)

// Tailer follows a Postfix mail log file and emits delivery events via the
// configured handler. It handles log rotation (the file being truncated or
// replaced) by periodically checking inode/size.
type Tailer struct {
	path    string
	handler Handler
	logger  *slog.Logger

	// queue_id → message_id; bounded size (LRU-ish via age + cap).
	mu      sync.Mutex
	queueMap map[string]queueEntry
	// cap limits how many queue_id entries we cache at once.
	cap int
	// ttl discards entries older than this regardless of cap.
	ttl time.Duration

	stopCh chan struct{}
	doneCh chan struct{}
}

type queueEntry struct {
	messageID string
	insertedAt time.Time
}

// Options configures a Tailer. Handler and Path are required.
type Options struct {
	Path    string
	Handler Handler
	Logger  *slog.Logger
	// MaxQueueEntries bounds the queue_id → message_id cache. Default: 10_000.
	MaxQueueEntries int
	// QueueEntryTTL is the max lifetime of an unclaimed queue_id → message_id
	// mapping. A successful SMTP delivery is usually logged within seconds;
	// deferred mail can sit for days, so we keep entries for 7 days by default.
	QueueEntryTTL time.Duration
}

// New constructs a Tailer. It does not open the file until Start is called.
func New(opts Options) *Tailer {
	cap := opts.MaxQueueEntries
	if cap <= 0 {
		cap = 10_000
	}
	ttl := opts.QueueEntryTTL
	if ttl <= 0 {
		ttl = 7 * 24 * time.Hour
	}
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Tailer{
		path:     opts.Path,
		handler:  opts.Handler,
		logger:   logger,
		queueMap: make(map[string]queueEntry),
		cap:      cap,
		ttl:      ttl,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

// Start begins tailing the log file in a goroutine. It is safe to call Start
// before the file exists — the tailer will poll until it appears.
func (t *Tailer) Start() {
	go t.run()
}

// Stop signals the tailer to stop and waits for the tailing goroutine to exit.
// Safe to call multiple times.
func (t *Tailer) Stop() {
	select {
	case <-t.stopCh:
		// already stopped
	default:
		close(t.stopCh)
	}
	<-t.doneCh
}

func (t *Tailer) run() {
	defer close(t.doneCh)
	t.logger.Info("postfix log tailer starting", "path", t.path)

	// Pruning ticker for expired queue map entries.
	pruneTicker := time.NewTicker(1 * time.Hour)
	defer pruneTicker.Stop()
	go func() {
		for {
			select {
			case <-t.stopCh:
				return
			case <-pruneTicker.C:
				t.pruneQueueMap()
			}
		}
	}()

	// Outer loop: open, tail, reopen on rotation or error.
	for {
		select {
		case <-t.stopCh:
			return
		default:
		}

		if err := t.tailOnce(); err != nil {
			t.logger.Warn("postfix log tailer iteration ended", "error", err)
		}

		// Brief backoff before reopening (file missing, rotated, etc).
		select {
		case <-t.stopCh:
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// tailOnce opens the file, seeks to the end, and reads lines until EOF
// or the file is rotated (detected via inode change on periodic stat).
func (t *Tailer) tailOnce() error {
	f, err := os.Open(t.path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Seek to end on first open so we don't reprocess historical lines.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return err
	}

	origStat, err := f.Stat()
	if err != nil {
		return err
	}
	origInode := inode(origStat)

	reader := bufio.NewReader(f)

	rotateCheckTicker := time.NewTicker(5 * time.Second)
	defer rotateCheckTicker.Stop()

	for {
		select {
		case <-t.stopCh:
			return nil
		case <-rotateCheckTicker.C:
			// Check for rotation: different inode or file shrunk.
			st, err := os.Stat(t.path)
			if err != nil {
				return err
			}
			if inode(st) != origInode || st.Size() < origStat.Size() {
				return nil // caller will reopen
			}
		default:
		}

		line, err := reader.ReadString('\n')
		if err == io.EOF {
			// No data yet — sleep briefly and try again.
			select {
			case <-t.stopCh:
				return nil
			case <-time.After(250 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			return err
		}

		t.processLine(strings.TrimRight(line, "\n"))
	}
}

var (
	// Match postfix component + queue_id + rest of message body.
	//   ... postfix/<component>[<pid>]: <QUEUEID>: <rest>
	reLogLine = regexp.MustCompile(`postfix/(\w+)\[\d+\]:\s+([A-F0-9]{6,}):\s+(.*)$`)

	// Message-ID inside a cleanup line.
	reMessageID = regexp.MustCompile(`message-id=<?([^>\s,]+)>?`)

	// Fields inside a smtp delivery line.
	reTo       = regexp.MustCompile(`to=<([^>]*)>`)
	reRelay    = regexp.MustCompile(`relay=([^,\s]+)`)
	reDSN      = regexp.MustCompile(`dsn=([0-9.]+)`)
	reStatus   = regexp.MustCompile(`status=(\w+)\s*(?:\((.*)\))?`)
	reDelay    = regexp.MustCompile(`\bdelay=([0-9.]+)`)
)

// processLine parses a single Postfix log line and, if it contains a delivery
// event we care about, emits it via the handler.
func (t *Tailer) processLine(line string) {
	m := reLogLine.FindStringSubmatch(line)
	if m == nil {
		return
	}
	component := m[1]
	queueID := m[2]
	rest := m[3]

	switch component {
	case "cleanup":
		// Extract the Message-ID and record queue_id → message_id.
		if idm := reMessageID.FindStringSubmatch(rest); idm != nil {
			t.rememberQueueID(queueID, idm[1])
		}
	case "smtp", "lmtp", "pipe", "error":
		// Delivery attempt. Only care when a `status=` field is present.
		sm := reStatus.FindStringSubmatch(rest)
		if sm == nil {
			return
		}
		status := sm[1]
		var evType EventType
		switch status {
		case "sent":
			evType = EventDelivered
		case "bounced":
			evType = EventBounced
		case "deferred":
			evType = EventDeferred
		default:
			return
		}

		// mail.delivered fires for BOTH smtp (external relay) and lmtp
		// (Dovecot on our own cluster) deliveries. The sender-facing
		// semantic of "your mail reached its destination mailserver" is
		// the same in both cases — cross-domain within Vectis is still a
		// successful delivery from the sender's perspective. The
		// complementary mail.received event (fired by the inbound pipeline
		// for the recipient's domain owner) is a different audience.
		ev := Event{
			Type:      evType,
			QueueID:   queueID,
			Status:    status,
			Timestamp: time.Now().UTC(),
			MessageID: t.lookupQueueID(queueID),
		}
		if len(sm) > 2 {
			ev.Response = strings.TrimSpace(sm[2])
		}
		if tm := reTo.FindStringSubmatch(rest); tm != nil {
			ev.Recipient = tm[1]
		}
		if rm := reRelay.FindStringSubmatch(rest); rm != nil {
			ev.Relay = rm[1]
		}
		if dm := reDSN.FindStringSubmatch(rest); dm != nil {
			ev.DSN = dm[1]
		}
		if dlm := reDelay.FindStringSubmatch(rest); dlm != nil {
			if d, err := strconv.ParseFloat(dlm[1], 64); err == nil {
				ev.Delay = d
			}
		}

		if t.handler != nil {
			t.handler(context.Background(), ev)
		}
	}
}

// rememberQueueID stores a queue_id → message_id mapping, enforcing the cap.
func (t *Tailer) rememberQueueID(queueID, messageID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// If at cap, drop the oldest entry (any map entry works for O(1)
	// eviction; not strict LRU but good enough for this use case).
	if len(t.queueMap) >= t.cap {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range t.queueMap {
			if oldestKey == "" || v.insertedAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.insertedAt
			}
		}
		delete(t.queueMap, oldestKey)
	}

	t.queueMap[queueID] = queueEntry{
		messageID:  messageID,
		insertedAt: time.Now(),
	}
}

// lookupQueueID returns the message_id associated with a queue_id, or "" if
// no mapping was recorded. The mapping is retained (not deleted) because a
// single queued message can produce multiple delivery events (one per
// recipient) and we want all of them resolvable.
func (t *Tailer) lookupQueueID(queueID string) string {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.queueMap[queueID]; ok {
		return e.messageID
	}
	return ""
}

// pruneQueueMap discards queue entries older than ttl.
func (t *Tailer) pruneQueueMap() {
	cutoff := time.Now().Add(-t.ttl)
	t.mu.Lock()
	defer t.mu.Unlock()
	for k, v := range t.queueMap {
		if v.insertedAt.Before(cutoff) {
			delete(t.queueMap, k)
		}
	}
}

// inode returns a stable file identifier. On Linux the Ino field is populated;
// on other platforms we fall back to ModTime+Size which is less precise but
// adequate for rotation detection (the tailer will reopen spuriously once
// per ModTime change which is fine).
func inode(fi os.FileInfo) uint64 {
	return inodeOS(fi)
}
