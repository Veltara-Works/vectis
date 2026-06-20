package license

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestRefresherInitialLoadPopulatesProvider(t *testing.T) {
	p := NewProvider(NewResolver("", "")) // embedded-only: always loads
	r := NewRefresher(p, time.Hour, quietLogger())

	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	if p.Current() == nil {
		t.Fatal("provider keyset should be populated synchronously by Start")
	}
	if p.Source() != SourceEmbedded {
		t.Fatalf("source: got %q, want embedded", p.Source())
	}
}

func TestRefresherStartFailsWhenEveryLayerFails(t *testing.T) {
	p := NewProvider(&Resolver{Embedded: nil}) // no live, no cache, no embedded
	r := NewRefresher(p, time.Hour, quietLogger())
	if err := r.Start(context.Background()); err == nil {
		t.Fatal("expected Start to fail when the initial load has no usable layer")
	}
}

func TestRefresherTriggerForcesRefresh(t *testing.T) {
	p := NewProvider(NewResolver("", ""))
	r := NewRefresher(p, time.Hour, quietLogger()) // long interval: no tick interferes
	seen := make(chan Source, 4)
	r.onRefresh = seen

	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	r.Trigger()
	select {
	case src := <-seen:
		if src != SourceEmbedded {
			t.Fatalf("triggered refresh source: got %q, want embedded", src)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("triggered refresh did not run")
	}
}

func TestRefresherFailedRefreshKeepsLastGoodSource(t *testing.T) {
	p := NewProvider(NewResolver("", "")) // initial load succeeds (embedded)
	r := NewRefresher(p, time.Hour, quietLogger())
	seen := make(chan Source, 4)
	r.onRefresh = seen

	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	// Break the resolver so the next refresh fails. The Trigger send below
	// happens-before the loop reads p.resolver, so this is race-free.
	p.resolver = &Resolver{Embedded: nil}
	r.Trigger()

	select {
	case src := <-seen:
		if src != SourceEmbedded {
			t.Fatalf("failed refresh should report last-good source, got %q", src)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no refresh signal after trigger")
	}
	if p.Current() == nil {
		t.Fatal("keyset must be retained after a failed refresh")
	}
}

func TestRefresherTicksPeriodically(t *testing.T) {
	p := NewProvider(NewResolver("", ""))
	r := NewRefresher(p, 10*time.Millisecond, quietLogger())
	seen := make(chan Source, 16)
	r.onRefresh = seen

	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer r.Stop()

	// Expect at least two background ticks within a generous window.
	deadline := time.After(2 * time.Second)
	for i := 0; i < 2; i++ {
		select {
		case <-seen:
		case <-deadline:
			t.Fatalf("only observed %d periodic refreshes", i)
		}
	}
}

func TestRefresherStopHaltsLoop(t *testing.T) {
	p := NewProvider(NewResolver("", ""))
	r := NewRefresher(p, 10*time.Millisecond, quietLogger())
	seen := make(chan Source, 64)
	r.onRefresh = seen

	if err := r.Start(context.Background()); err != nil {
		t.Fatalf("start: %v", err)
	}
	r.Stop()

	// Drain anything already queued, then assert the loop has gone quiet.
	time.Sleep(50 * time.Millisecond)
	for {
		select {
		case <-seen:
			continue
		default:
		}
		break
	}
	select {
	case <-seen:
		t.Fatal("refresher kept ticking after Stop")
	case <-time.After(100 * time.Millisecond):
		// no further refreshes: loop stopped as expected
	}
}
