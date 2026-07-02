package api

import (
	"net/http"
	"sync"
	"time"
)

// fixedWindowLimiter is a small per-key fixed-window rate limiter. It bounds the
// number of events per key within a rolling window. The password-reset
// endpoints previously had only chi Throttle, which bounds in-flight
// concurrency, not rate — sequential requests all passed, enabling reset-email
// bombing and unbounded reset_tokens growth (audit D-L2).
type fixedWindowLimiter struct {
	mu        sync.Mutex
	limit     int
	window    time.Duration
	events    map[string][]time.Time
	calls     int
	sweepEach int
}

func newFixedWindowLimiter(limit int, window time.Duration) *fixedWindowLimiter {
	return &fixedWindowLimiter{
		limit:     limit,
		window:    window,
		events:    make(map[string][]time.Time),
		sweepEach: 1024,
	}
}

// allow records an attempt for key at now and reports whether it is within the
// limit. Stale timestamps are pruned per-key on touch, and the whole map is
// swept for empty/stale keys every sweepEach calls so memory stays bounded
// under a churn of unique IPs.
func (l *fixedWindowLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.calls++
	if l.calls%l.sweepEach == 0 {
		l.sweepLocked(now)
	}

	cutoff := now.Add(-l.window)
	kept := l.events[key][:0]
	for _, t := range l.events[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.limit {
		l.events[key] = kept
		return false
	}
	l.events[key] = append(kept, now)
	return true
}

// sweepLocked drops keys whose events are all older than the window. Caller
// holds l.mu.
func (l *fixedWindowLimiter) sweepLocked(now time.Time) {
	cutoff := now.Add(-l.window)
	for k, times := range l.events {
		fresh := false
		for _, t := range times {
			if t.After(cutoff) {
				fresh = true
				break
			}
		}
		if !fresh {
			delete(l.events, k)
		}
	}
}

// rateLimitByIP is middleware that rejects requests from a client IP that has
// exceeded the limiter's window, returning 429. Used to bound the
// password-reset endpoints per source IP.
func (s *Server) rateLimitByIP(limiter *fixedWindowLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if limiter != nil && !limiter.allow("ip:"+clientIP(r), time.Now()) {
				respondError(w, r, http.StatusTooManyRequests, "RATE_LIMITED",
					"Too many requests. Please wait a few minutes and try again.")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
