package postfixlog

import (
	"context"
	"sync"
	"testing"
	"time"
)

// newTestTailer builds a Tailer without starting the goroutines, suitable
// for unit testing processLine directly.
func newTestTailer(handler Handler) *Tailer {
	return &Tailer{
		handler:  handler,
		queueMap: make(map[string]queueEntry),
		cap:      100,
		ttl:      time.Hour,
		stopCh:   make(chan struct{}),
		doneCh:   make(chan struct{}),
	}
}

func TestProcessLine_CleanupRecordsMessageID(t *testing.T) {
	tr := newTestTailer(func(ctx context.Context, ev Event) {
		t.Fatalf("cleanup should not emit an event, got %+v", ev)
	})

	tr.processLine(`Apr 18 12:00:00 host postfix/cleanup[1234]: ABCDEF12: message-id=<abc@mail.example.com>`)

	if got := tr.lookupQueueID("ABCDEF12"); got != "abc@mail.example.com" {
		t.Fatalf("expected message-id recorded, got %q", got)
	}
}

func TestProcessLine_DeliveredEmitsEvent(t *testing.T) {
	var got Event
	var gotMu sync.Mutex
	tr := newTestTailer(func(ctx context.Context, ev Event) {
		gotMu.Lock()
		got = ev
		gotMu.Unlock()
	})

	tr.rememberQueueID("ABCDEF12", "abc@mail.example.com")
	tr.processLine(`Apr 18 12:00:01 host postfix/smtp[5678]: ABCDEF12: to=<user@example.com>, relay=mx.example.com[1.2.3.4]:25, delay=0.5, delays=0.1/0/0.2/0.2, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as 123456)`)

	if got.Type != EventDelivered {
		t.Fatalf("expected delivered, got %s", got.Type)
	}
	if got.MessageID != "abc@mail.example.com" {
		t.Fatalf("expected message_id resolved, got %q", got.MessageID)
	}
	if got.Recipient != "user@example.com" {
		t.Fatalf("expected recipient extracted, got %q", got.Recipient)
	}
	if got.Relay != "mx.example.com[1.2.3.4]:25" {
		t.Fatalf("expected relay extracted, got %q", got.Relay)
	}
	if got.DSN != "2.0.0" {
		t.Fatalf("expected dsn=2.0.0, got %q", got.DSN)
	}
	if got.Delay != 0.5 {
		t.Fatalf("expected delay=0.5, got %v", got.Delay)
	}
	if got.Response != "250 2.0.0 Ok: queued as 123456" {
		t.Fatalf("expected full SMTP response, got %q", got.Response)
	}
}

func TestProcessLine_BouncedEmitsEvent(t *testing.T) {
	var got Event
	tr := newTestTailer(func(ctx context.Context, ev Event) { got = ev })

	tr.rememberQueueID("ABCDEF12", "abc@mail.example.com")
	tr.processLine(`Apr 18 12:00:01 host postfix/smtp[5678]: ABCDEF12: to=<user@example.com>, relay=mx.example.com[1.2.3.4]:25, delay=1.0, delays=0.1/0/0.2/0.7, dsn=5.1.1, status=bounced (host mx.example.com said: 550 5.1.1 <user@example.com>: User unknown in virtual mailbox table (in reply to RCPT TO command))`)

	if got.Type != EventBounced {
		t.Fatalf("expected bounced, got %s", got.Type)
	}
	if got.DSN != "5.1.1" {
		t.Fatalf("expected dsn=5.1.1, got %q", got.DSN)
	}
	if got.MessageID != "abc@mail.example.com" {
		t.Fatalf("expected message_id resolved, got %q", got.MessageID)
	}
}

func TestProcessLine_DeferredEmitsEvent(t *testing.T) {
	var got Event
	tr := newTestTailer(func(ctx context.Context, ev Event) { got = ev })

	tr.rememberQueueID("DEADBEEF", "xyz@mail.example.com")
	tr.processLine(`postfix/smtp[1]: DEADBEEF: to=<x@y.com>, relay=none, delay=300, delays=0/0/300/0, dsn=4.4.1, status=deferred (connect to y.com[1.1.1.1]:25: Connection timed out)`)

	if got.Type != EventDeferred {
		t.Fatalf("expected deferred, got %s", got.Type)
	}
}

func TestProcessLine_LMTPIgnored(t *testing.T) {
	tr := newTestTailer(func(ctx context.Context, ev Event) {
		t.Fatalf("LMTP deliveries (local Dovecot) must not emit events, got %+v", ev)
	})
	tr.rememberQueueID("ABCDEF12", "abc@mail.example.com")
	tr.processLine(`postfix/lmtp[5678]: ABCDEF12: to=<mail@local.example.com>, relay=dovecot[172.19.0.4]:24, delay=0.1, status=sent (250 2.0.0 <mail@local.example.com> Sfkz... Saved)`)
}

func TestProcessLine_NoQueueIDMapping(t *testing.T) {
	// When no cleanup line preceded the delivery (e.g. tailer started mid-run),
	// we still emit the event but with an empty MessageID. The server-side
	// resolver can then skip dispatch.
	var got Event
	tr := newTestTailer(func(ctx context.Context, ev Event) { got = ev })

	tr.processLine(`postfix/smtp[1]: FEEDFACE: to=<u@e.com>, relay=mx.e.com[1.2.3.4]:25, delay=1, dsn=2.0.0, status=sent (250 OK)`)

	if got.Type != EventDelivered {
		t.Fatalf("expected delivered, got %s", got.Type)
	}
	if got.MessageID != "" {
		t.Fatalf("expected empty message_id, got %q", got.MessageID)
	}
	if got.QueueID != "FEEDFACE" {
		t.Fatalf("expected queue_id preserved, got %q", got.QueueID)
	}
}

func TestProcessLine_NonMailLinesIgnored(t *testing.T) {
	tr := newTestTailer(func(ctx context.Context, ev Event) {
		t.Fatalf("non-delivery lines must not emit events, got %+v", ev)
	})
	tr.processLine(`postfix/master[1]: daemon started -- version 3.9.1, configuration /etc/postfix`)
	tr.processLine(`postfix/qmgr[2]: ABCDEF12: from=<s@e.com>, size=1234, nrcpt=1 (queue active)`)
	tr.processLine(`some completely unrelated line that is not postfix at all`)
}

func TestQueueMapEviction(t *testing.T) {
	tr := newTestTailer(nil)
	tr.cap = 3

	tr.rememberQueueID("A", "a@x")
	time.Sleep(2 * time.Millisecond)
	tr.rememberQueueID("B", "b@x")
	time.Sleep(2 * time.Millisecond)
	tr.rememberQueueID("C", "c@x")
	// Now at cap. Adding D should evict the oldest (A).
	time.Sleep(2 * time.Millisecond)
	tr.rememberQueueID("D", "d@x")

	if tr.lookupQueueID("A") != "" {
		t.Fatalf("expected A to be evicted")
	}
	if tr.lookupQueueID("D") != "d@x" {
		t.Fatalf("expected D to be present")
	}
}
