package mail

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// fakeWarmupStore keeps entries in memory and applies Reserve the way the SQL
// does: the oldest active entry, all of n or nothing.
type fakeWarmupStore struct {
	mu      sync.Mutex
	entries []repository.IPWarmup
	err     error
}

func (f *fakeWarmupStore) List(context.Context) ([]repository.IPWarmup, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]repository.IPWarmup(nil), f.entries...), f.err
}

func (f *fakeWarmupStore) Reserve(_ context.Context, n int) (*repository.IPWarmup, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, false, f.err
	}
	for i := range f.entries {
		e := &f.entries[i]
		if !e.Active {
			continue
		}
		if e.DailySent+n > e.DailyLimit {
			c := *e
			return &c, false, nil
		}
		e.DailySent += n
		c := *e
		return &c, true, nil
	}
	return nil, false, nil
}

func (f *fakeWarmupStore) Release(_ context.Context, id string, n int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.entries {
		if f.entries[i].ID == id {
			f.entries[i].DailySent = max(f.entries[i].DailySent-n, 0)
		}
	}
	return nil
}

func (f *fakeWarmupStore) AdvanceDay(_ context.Context, id string, newDay, newLimit int, resetAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.entries {
		if f.entries[i].ID == id {
			e := &f.entries[i]
			e.WarmupDay, e.DailyLimit, e.DailySent, e.LastResetAt = newDay, newLimit, 0, resetAt
		}
	}
	return nil
}

func (f *fakeWarmupStore) Deactivate(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.entries {
		if f.entries[i].ID == id {
			f.entries[i].Active = false
		}
	}
	return nil
}

func (f *fakeWarmupStore) get(t *testing.T) repository.IPWarmup {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.entries) != 1 {
		t.Fatalf("store has %d entries, want 1", len(f.entries))
	}
	return f.entries[0]
}

var warmupT0 = time.Date(2026, 10, 1, 6, 0, 0, 0, time.UTC)

func newTestWarmup(entries ...repository.IPWarmup) (*WarmupManager, *fakeWarmupStore, *time.Time) {
	store := &fakeWarmupStore{entries: entries}
	m := NewWarmupManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := warmupT0
	m.now = func() time.Time { return now }
	return m, store, &now
}

func dayOne() repository.IPWarmup {
	return repository.IPWarmup{ID: "w1", IPAddress: "203.0.113.7/32", WarmupDay: 1, DailyLimit: 50,
		LastResetAt: warmupT0, Active: true}
}

func TestWarmupReserveUnlimitedWithoutAnActiveWarmup(t *testing.T) {
	m, _, _ := newTestWarmup()
	d, err := m.Reserve(context.Background(), 1000)
	if err != nil || !d.Allowed || d.Limited {
		t.Fatalf("Reserve with no warmup = %+v, %v; want allowed and unlimited", d, err)
	}

	inactive := dayOne()
	inactive.Active = false
	m, _, _ = newTestWarmup(inactive)
	if d, _ := m.Reserve(context.Background(), 1000); !d.Allowed || d.Limited {
		t.Fatalf("Reserve with an inactive warmup = %+v; want allowed and unlimited", d)
	}
}

func TestWarmupReserveIsAllOrNothingAtTheLimit(t *testing.T) {
	m, store, _ := newTestWarmup(dayOne())
	ctx := context.Background()

	if d, _ := m.Reserve(ctx, 30); !d.Allowed || !d.Limited || d.Sent != 30 || d.Limit != 50 {
		t.Fatalf("Reserve(30) = %+v; want allowed, 30 of 50", d)
	}
	d, _ := m.Reserve(ctx, 21)
	if d.Allowed || d.Sent != 30 {
		t.Fatalf("Reserve(21) past the limit = %+v; want refused with 30 still sent", d)
	}
	if !d.ResetAt.Equal(warmupT0.Add(24 * time.Hour)) {
		t.Errorf("ResetAt = %v, want a day after the last reset", d.ResetAt)
	}
	if d, _ := m.Reserve(ctx, 20); !d.Allowed || d.Sent != 50 {
		t.Fatalf("Reserve(20) to exactly the limit = %+v; want allowed, 50 sent", d)
	}
	if d, _ := m.Reserve(ctx, 1); d.Allowed {
		t.Fatal("Reserve(1) at the limit was allowed")
	}
	if got := store.get(t).DailySent; got != 50 {
		t.Errorf("DailySent = %d, want 50", got)
	}
}

func TestWarmupReleaseReturnsReservedSends(t *testing.T) {
	m, store, _ := newTestWarmup(dayOne())
	ctx := context.Background()
	d, _ := m.Reserve(ctx, 10)
	m.Release(ctx, d, 10)
	if got := store.get(t).DailySent; got != 0 {
		t.Fatalf("DailySent after release = %d, want 0", got)
	}

	refused, _ := m.Reserve(ctx, 51)
	m.Release(ctx, refused, 51) // nothing was reserved, so nothing to give back
	m.Release(ctx, WarmupDecision{Allowed: true}, 5)
	if got := store.get(t).DailySent; got != 0 {
		t.Errorf("DailySent after releasing refused/unlimited decisions = %d, want 0", got)
	}
}

func TestWarmupReserveFailsOpenOnStoreError(t *testing.T) {
	m, store, _ := newTestWarmup(dayOne())
	store.err = errors.New("db down")
	d, err := m.Reserve(context.Background(), 5)
	if err == nil || !d.Allowed {
		t.Fatalf("Reserve on a store error = %+v, %v; want allowed with the error", d, err)
	}
}

func TestWarmupAdvanceKeepsTheResetTimeOfDay(t *testing.T) {
	m, store, now := newTestWarmup(dayOne())
	ctx := context.Background()

	*now = warmupT0.Add(23*time.Hour + 59*time.Minute)
	m.advanceSchedules(ctx)
	if e := store.get(t); e.WarmupDay != 1 {
		t.Fatalf("advanced to day %d before a full day had passed", e.WarmupDay)
	}

	// Noticed 4 minutes late: the next reset is still at 06:00.
	*now = warmupT0.Add(24*time.Hour + 4*time.Minute)
	m.advanceSchedules(ctx)
	e := store.get(t)
	if e.WarmupDay != 2 || e.DailyLimit != repository.WarmupSchedule(2) || e.DailySent != 0 {
		t.Fatalf("after one day = day %d, limit %d, sent %d; want day 2 at its scheduled limit, 0 sent",
			e.WarmupDay, e.DailyLimit, e.DailySent)
	}
	if want := warmupT0.Add(24 * time.Hour); !e.LastResetAt.Equal(want) {
		t.Errorf("LastResetAt = %v, want %v", e.LastResetAt, want)
	}

	// Down for three and a half days: one day of the ramp, reset still at 06:00.
	*now = warmupT0.Add(4*24*time.Hour + 12*time.Hour)
	m.advanceSchedules(ctx)
	e = store.get(t)
	if e.WarmupDay != 3 {
		t.Errorf("after missed days WarmupDay = %d, want 3 (one step per pass)", e.WarmupDay)
	}
	if want := warmupT0.Add(4 * 24 * time.Hour); !e.LastResetAt.Equal(want) {
		t.Errorf("after missed days LastResetAt = %v, want %v", e.LastResetAt, want)
	}
}

func TestWarmupReserveAdvancesADayThatIsDue(t *testing.T) {
	full := dayOne()
	full.DailySent = 50
	m, _, now := newTestWarmup(full)

	*now = warmupT0.Add(24*time.Hour + time.Second) // the loop hasn't run yet
	d, err := m.Reserve(context.Background(), 1)
	if err != nil || !d.Allowed || d.Day != 2 || d.Sent != 1 {
		t.Fatalf("Reserve just after the reset was due = %+v, %v; want allowed on day 2 with 1 sent", d, err)
	}
}

func TestWarmupCompletesAfterTheLastDay(t *testing.T) {
	last := dayOne()
	last.WarmupDay = WarmupDays
	last.DailyLimit = repository.WarmupSchedule(WarmupDays)
	m, store, now := newTestWarmup(last)

	*now = warmupT0.Add(24 * time.Hour)
	m.advanceSchedules(context.Background())
	if store.get(t).Active {
		t.Fatal("warmup still active after its last day")
	}
	if d, _ := m.Reserve(context.Background(), 1_000_000); !d.Allowed || d.Limited {
		t.Errorf("Reserve after completion = %+v; want unlimited", d)
	}
}

func TestWarmupRetryAfter(t *testing.T) {
	d := WarmupDecision{ResetAt: warmupT0.Add(90 * time.Minute)}
	if got := d.RetryAfter(warmupT0); got != 90*time.Minute {
		t.Errorf("RetryAfter = %v, want 90m", got)
	}
	if got := d.RetryAfter(warmupT0.Add(2 * time.Hour)); got != time.Minute {
		t.Errorf("RetryAfter past the reset = %v, want the 1m floor", got)
	}
}
