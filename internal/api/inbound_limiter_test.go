package api

import (
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
)

func TestInboundAsyncLimiterAcquire(t *testing.T) {
	l := newInboundAsyncLimiter(100)
	if !l.acquire(60) {
		t.Fatal("first 60 should be admitted (budget 100)")
	}
	if !l.acquire(40) {
		t.Fatal("40 more fits exactly within 100")
	}
	if l.acquire(1) {
		t.Fatal("over budget with work in flight must be dropped")
	}
	l.release(40)
	if !l.acquire(40) {
		t.Fatal("after release, 40 fits again")
	}
}

// TestInboundAsyncLimiterOversizedAdmittedWhenIdle proves a single message
// larger than the whole budget is still processed (alone) rather than dropped
// forever — but blocks everything else while in flight.
func TestInboundAsyncLimiterOversizedAdmittedWhenIdle(t *testing.T) {
	l := newInboundAsyncLimiter(100)
	if !l.acquire(500) {
		t.Fatal("oversized task must be admitted when nothing is in flight")
	}
	if l.acquire(1) {
		t.Fatal("while the oversized task is in flight, others must be dropped")
	}
	l.release(500)
	if l.inFlight != 0 {
		t.Fatalf("inFlight = %d, want 0", l.inFlight)
	}
}

func TestInboundAsyncLimiterReleaseClampsAtZero(t *testing.T) {
	l := newInboundAsyncLimiter(100)
	l.acquire(10)
	l.release(50) // over-release
	if l.inFlight != 0 {
		t.Fatalf("inFlight = %d, want clamped to 0", l.inFlight)
	}
}

// TestInboundAsyncLimiterConcurrent exercises the mutex under -race.
func TestInboundAsyncLimiterConcurrent(t *testing.T) {
	l := newInboundAsyncLimiter(1000)
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if l.acquire(10) {
				l.release(10)
			}
		}()
	}
	wg.Wait()
	if l.inFlight != 0 {
		t.Fatalf("inFlight = %d, want 0 after all releases", l.inFlight)
	}
}

func testServerWithLimiter(max int64) *Server {
	return &Server{
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
		inboundAsync: newInboundAsyncLimiter(max),
	}
}

func TestSpawnInboundAsyncDropsWhenExhausted(t *testing.T) {
	s := testServerWithLimiter(100)
	s.inboundAsync.acquire(100) // exhaust the budget
	var ran atomic.Bool
	s.spawnInboundAsync("test", 50, func() { ran.Store(true) })
	if ran.Load() {
		t.Fatal("task should have been dropped (budget exhausted), not run")
	}
}

func TestSpawnInboundAsyncRunsWhenAdmitted(t *testing.T) {
	s := testServerWithLimiter(100)
	done := make(chan struct{})
	s.spawnInboundAsync("test", 50, func() { close(done) })
	<-done // blocks forever if the task never ran
}

// TestSpawnInboundAsyncNilLimiterFallsBack confirms a bare Server (no limiter,
// as some tests construct) still runs the task directly.
func TestSpawnInboundAsyncNilLimiterFallsBack(t *testing.T) {
	s := &Server{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	done := make(chan struct{})
	s.spawnInboundAsync("test", 50, func() { close(done) })
	<-done
}
