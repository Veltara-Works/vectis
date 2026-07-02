package api

import (
	"testing"
	"time"
)

// TestFixedWindowLimiter locks the D-L2 rate-limit behaviour: N events per key
// per window are allowed, the next is denied, and the key recovers once the
// window elapses. Keys are independent.
func TestFixedWindowLimiter(t *testing.T) {
	l := newFixedWindowLimiter(3, time.Minute)
	base := time.Unix(1_700_000_000, 0)

	for i := 0; i < 3; i++ {
		if !l.allow("ip:1.2.3.4", base) {
			t.Fatalf("attempt %d should be allowed within limit", i+1)
		}
	}
	if l.allow("ip:1.2.3.4", base) {
		t.Fatal("4th attempt in window should be denied")
	}

	// A different key is unaffected.
	if !l.allow("ip:9.9.9.9", base) {
		t.Fatal("independent key should be allowed")
	}

	// After the window elapses the original key recovers.
	if !l.allow("ip:1.2.3.4", base.Add(2*time.Minute)) {
		t.Fatal("key should recover after the window elapses")
	}
}

// TestFixedWindowLimiter_Sweep ensures stale keys are eventually pruned so the
// map doesn't grow unbounded under unique-IP churn.
func TestFixedWindowLimiter_Sweep(t *testing.T) {
	l := newFixedWindowLimiter(1, time.Minute)
	l.sweepEach = 4
	base := time.Unix(1_700_000_000, 0)

	// Touch several one-off keys long in the past, then trigger a sweep well
	// after the window; all stale keys should be dropped.
	l.allow("a", base)
	l.allow("b", base)
	l.allow("c", base)
	l.allow("d", base.Add(time.Hour)) // 4th call → sweep at "now = base+1h"

	l.mu.Lock()
	defer l.mu.Unlock()
	if _, ok := l.events["a"]; ok {
		t.Fatal("stale key a should have been swept")
	}
	if _, ok := l.events["d"]; !ok {
		t.Fatal("fresh key d should survive the sweep")
	}
}
