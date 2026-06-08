// Package ratelimit provides Valkey-backed request rate limiting.
//
// The fixed-window primitive here is deliberately caller-namespaced: the caller
// supplies the full Valkey key, so the same limiter backs per-API-key budgets
// today and per-tenant or per-IP budgets later without changing this package.
package ratelimit

import (
	"context"
	"strconv"
	"time"

	"github.com/valkey-io/valkey-go"
)

// fixedWindowScript atomically increments the window counter and, only on the
// first request of a window, arms the window TTL. Running the INCR+EXPIRE as one
// server-side script removes the orphaned-counter race a separate INCR-then-
// EXPIRE would suffer if the process died between the two calls (the counter
// would then never reset).
const fixedWindowScript = `local n = redis.call("INCR", KEYS[1])
if n == 1 then redis.call("EXPIRE", KEYS[1], ARGV[1]) end
return n`

// Result reports the outcome of an Allow check.
type Result struct {
	Allowed   bool  // false once the window count exceeds the limit
	Limit     int   // the configured per-window budget
	Remaining int   // requests left in the current window (>= 0); -1 when unlimited
	Count     int64 // requests recorded so far in the current window
}

// Allow records one request against key's fixed window and reports whether it
// is within limit. limit <= 0 means "unlimited": Allow returns Allowed=true
// without touching Valkey. window is the budget period (e.g. time.Minute) and
// is rounded up to whole seconds (minimum 1s, Valkey's EXPIRE granularity).
func Allow(ctx context.Context, vk valkey.Client, key string, limit int, window time.Duration) (Result, error) {
	if limit <= 0 {
		return Result{Allowed: true, Limit: limit, Remaining: -1}, nil
	}
	windowSecs := int((window + time.Second - 1) / time.Second)
	if windowSecs < 1 {
		windowSecs = 1
	}

	cmd := vk.B().Eval().Script(fixedWindowScript).Numkeys(1).Key(key).Arg(strconv.Itoa(windowSecs)).Build()
	count, err := vk.Do(ctx, cmd).ToInt64()
	if err != nil {
		return Result{}, err
	}

	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}
	return Result{
		Allowed:   count <= int64(limit),
		Limit:     limit,
		Remaining: remaining,
		Count:     count,
	}, nil
}

// RetryAfter returns the time until key's current window resets, for a
// Retry-After header. It falls back to the full window on any TTL error or when
// the key has no expiry set (which should not happen for an Allow'd key).
func RetryAfter(ctx context.Context, vk valkey.Client, key string, window time.Duration) time.Duration {
	secs, err := vk.Do(ctx, vk.B().Ttl().Key(key).Build()).ToInt64()
	if err != nil || secs < 0 {
		return window
	}
	return time.Duration(secs) * time.Second
}
