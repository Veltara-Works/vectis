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

// fakeWarmupStore keeps entries in memory and applies the same conditions as
// the SQL: Reserve charges the oldest active entry, all of n or nothing, and
// only while its day is current; Release and AdvanceDay only touch the day
// they were given.
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

func (f *fakeWarmupStore) Reserve(_ context.Context, n int, dayStartedAfter time.Time) (*repository.IPWarmup, bool, error) {
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
		if e.DailySent+n > e.DailyLimit || !e.LastResetAt.After(dayStartedAfter) {
			c := *e
			return &c, false, nil
		}
		e.DailySent += n
		c := *e
		return &c, true, nil
	}
	return nil, false, nil
}

func (f *fakeWarmupStore) Release(_ context.Context, id string, n int, dayStart time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.entries {
		if f.entries[i].ID == id && f.entries[i].LastResetAt.Equal(dayStart) {
			f.entries[i].DailySent = max(f.entries[i].DailySent-n, 0)
		}
	}
	return nil
}

func (f *fakeWarmupStore) AdvanceDay(_ context.Context, id string, prevReset time.Time, newDay, newLimit int, resetAt time.Time) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i := range f.entries {
		if f.entries[i].ID == id && f.entries[i].LastResetAt.Equal(prevReset) {
			e := &f.entries[i]
			e.WarmupDay, e.DailyLimit, e.DailySent, e.LastResetAt = newDay, newLimit, 0, resetAt
			return true, nil
		}
	}
	return false, nil
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

// Copilot #288 finding 1: a send after the daily boundary, before the loop has
// advanced the day, is charged to the new day, not to yesterday's count.
func TestWarmupSendAfterTheBoundaryCountsAgainstTheNewDay(t *testing.T) {
	m, store, now := newTestWarmup(dayOne()) // day 1: 0 of 50 used
	ctx := context.Background()

	*now = warmupT0.Add(24*time.Hour + time.Second)
	if d, _ := m.Reserve(ctx, 50); !d.Allowed || d.Day != 2 || d.Sent != 50 {
		t.Fatalf("first send after the boundary = %+v; want allowed on day 2 with 50 sent", d)
	}
	if d, _ := m.Reserve(ctx, 50); d.Allowed {
		t.Fatalf("second 50 on day 2 (limit %d) was allowed", repository.WarmupSchedule(2))
	}
	if e := store.get(t); e.WarmupDay != 2 || e.DailySent != 50 {
		t.Errorf("entry = day %d, %d sent; want day 2, 50 sent", e.WarmupDay, e.DailySent)
	}
}

// Copilot #288 finding 6: a reservation made before the reset and released
// after it doesn't reduce the new day's count.
func TestWarmupReleaseAfterTheResetLeavesTheNewDayAlone(t *testing.T) {
	m, store, now := newTestWarmup(dayOne())
	ctx := context.Background()

	*now = warmupT0.Add(23 * time.Hour)
	old, _ := m.Reserve(ctx, 10)
	*now = warmupT0.Add(24*time.Hour + time.Minute)
	if d, _ := m.Reserve(ctx, 5); !d.Allowed || d.Day != 2 {
		t.Fatalf("send on day 2 = %+v; want allowed", d)
	}
	m.Release(ctx, old, 10) // the day-1 send failed after the reset
	if got := store.get(t).DailySent; got != 5 {
		t.Errorf("day 2 count after releasing a day-1 reservation = %d, want 5", got)
	}
}

// staleListStore serves List from a snapshot taken before another advance.
type staleListStore struct {
	*fakeWarmupStore
	snapshot []repository.IPWarmup
}

func (s staleListStore) List(context.Context) ([]repository.IPWarmup, error) { return s.snapshot, nil }

// Two advances working from the same listing (e.g. the loop and a refused
// send) must move the schedule on by one day, not two.
func TestWarmupAdvanceFromAStaleListingDoesNotSkipADay(t *testing.T) {
	store := &fakeWarmupStore{entries: []repository.IPWarmup{dayOne()}}
	stale := staleListStore{fakeWarmupStore: store, snapshot: append([]repository.IPWarmup(nil), store.entries...)}
	m := NewWarmupManager(stale, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.now = func() time.Time { return warmupT0.Add(24*time.Hour + time.Minute) }

	m.advanceSchedules(context.Background())
	m.advanceSchedules(context.Background()) // same stale listing
	if e := store.get(t); e.WarmupDay != 2 {
		t.Errorf("WarmupDay = %d after two advances from one listing, want 2", e.WarmupDay)
	}
}

// rolloverRaceStore simulates the loop advancing the day between the store's
// failed UPDATE and its read-back, once.
type rolloverRaceStore struct {
	*fakeWarmupStore
	raced bool
}

func (r *rolloverRaceStore) Reserve(ctx context.Context, n int, dayStartedAfter time.Time) (*repository.IPWarmup, bool, error) {
	if !r.raced {
		r.raced = true
		// The UPDATE saw day 1 (expired, full) and matched nothing; before the
		// read-back, the loop moves the entry on to day 2.
		if _, err := r.fakeWarmupStore.AdvanceDay(ctx, "w1", warmupT0, 2, repository.WarmupSchedule(2), warmupT0.Add(24*time.Hour)); err != nil {
			return nil, false, err
		}
		r.fakeWarmupStore.mu.Lock()
		e := r.fakeWarmupStore.entries[0]
		r.fakeWarmupStore.mu.Unlock()
		return &e, false, nil
	}
	return r.fakeWarmupStore.Reserve(ctx, n, dayStartedAfter)
}

// Copilot #288 review 4, previously missed 1: a refusal read back from a day
// that has just started, with room, is retried rather than refused for a day.
func TestWarmupReserveRetriesWhenTheDayAdvancesMidReservation(t *testing.T) {
	full := dayOne()
	full.DailySent = 50
	store := &rolloverRaceStore{fakeWarmupStore: &fakeWarmupStore{entries: []repository.IPWarmup{full}}}
	m := NewWarmupManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.now = func() time.Time { return warmupT0.Add(24*time.Hour + time.Second) }

	d, err := m.Reserve(context.Background(), 10)
	if err != nil || !d.Allowed || d.Day != 2 || d.Sent != 10 {
		t.Fatalf("Reserve across a concurrent rollover = %+v, %v; want allowed on day 2 with 10 sent", d, err)
	}
}

// failingAdvanceStore fails every AdvanceDay.
type failingAdvanceStore struct{ *fakeWarmupStore }

func (failingAdvanceStore) AdvanceDay(context.Context, string, time.Time, int, int, time.Time) (bool, error) {
	return false, errors.New("db down")
}

// Copilot #288 review 4, previously missed 2: a rollover that fails is a
// database error, so the send fails open with the error rather than being
// refused as over the limit.
func TestWarmupReserveFailsOpenWhenTheRolloverFails(t *testing.T) {
	full := dayOne()
	full.DailySent = 50
	store := failingAdvanceStore{&fakeWarmupStore{entries: []repository.IPWarmup{full}}}
	m := NewWarmupManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.now = func() time.Time { return warmupT0.Add(24*time.Hour + time.Second) }

	d, err := m.Reserve(context.Background(), 1)
	if err == nil || !d.Allowed {
		t.Fatalf("Reserve with a failing rollover = %+v, %v; want allowed with the error", d, err)
	}
}

// hangingReleaseStore's Release waits until its context is done.
type hangingReleaseStore struct{ *fakeWarmupStore }

func (hangingReleaseStore) Release(ctx context.Context, _ string, _ int, _ time.Time) error {
	<-ctx.Done()
	return ctx.Err()
}

// Copilot #288 review 6: a refund can't hold up the request that triggered
// it; it runs under its own deadline, even when the caller's ctx has none.
func TestWarmupReleaseIsBounded(t *testing.T) {
	store := hangingReleaseStore{&fakeWarmupStore{entries: []repository.IPWarmup{dayOne()}}}
	m := NewWarmupManager(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	m.now = func() time.Time { return warmupT0 }
	m.release = 50 * time.Millisecond
	d, _ := m.Reserve(context.Background(), 1)

	start := time.Now()
	m.Release(context.Background(), d, 1)
	if took := time.Since(start); took > time.Second {
		t.Errorf("Release took %v against a hung store, want about %v", took, m.release)
	}
}

// Copilot #288 review 7, previously missed: a send waiting for the rollover
// lock honours its own deadline, failing open, instead of hanging behind a
// stalled background pass.
func TestWarmupReserveDoesNotHangBehindAStalledRollover(t *testing.T) {
	full := dayOne()
	full.DailySent = 50
	m, _, now := newTestWarmup(full)
	*now = warmupT0.Add(24*time.Hour + time.Second) // the day is due to roll over

	m.advanceLock <- struct{}{} // a background pass holds the lock and is stuck
	defer func() { <-m.advanceLock }()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	d, err := m.Reserve(ctx, 1)
	if took := time.Since(start); took > time.Second {
		t.Fatalf("Reserve waited %v behind a stalled rollover, want about 50ms", took)
	}
	if err == nil || !d.Allowed {
		t.Errorf("Reserve behind a stalled rollover = %+v, %v; want allowed (fail open) with the context error", d, err)
	}
}
