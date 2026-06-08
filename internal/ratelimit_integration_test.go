//go:build integration

package internal_test

// Integration tests for the Valkey-backed fixed-window limiter that enforces
// api_keys.rate_limit. Lives in the internal/ package (not internal/ratelimit/)
// so CI's non-recursive `go test -tags integration ./internal/` actually runs
// it; the Valkey connection reuses the same VECTIS_TEST_VK_* env helpers as the
// other integration suites. Valkey is provided by CI.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/ratelimit"
	"github.com/valkey-io/valkey-go"
)

func newTestValkey(t *testing.T) valkey.Client {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	vk, err := database.NewValkeyClient(database.ValkeyConfig{
		Host:     envOr("VECTIS_TEST_VK_HOST", "127.0.0.1"),
		Port:     envOrInt("VECTIS_TEST_VK_PORT", 6379),
		Password: envOr("VECTIS_TEST_VK_PASSWORD", "vectis_dev_valkey"),
	}, logger)
	if err != nil {
		t.Fatalf("connect valkey: %v", err)
	}
	t.Cleanup(func() { vk.Close() })
	return vk
}

// uniqueKey keeps each test (and each run) isolated so stale counters from a
// prior run never bleed in.
func uniqueKey(t *testing.T) string {
	return fmt.Sprintf("test:ratelimit:%s:%d", t.Name(), time.Now().UnixNano())
}

func TestRateLimit_UnderThenOverLimit(t *testing.T) {
	vk := newTestValkey(t)
	ctx := context.Background()
	key := uniqueKey(t)
	const limit = 5

	for i := 1; i <= limit; i++ {
		res, err := ratelimit.Allow(ctx, vk, key, limit, time.Minute)
		if err != nil {
			t.Fatalf("Allow #%d: %v", i, err)
		}
		if !res.Allowed {
			t.Fatalf("request #%d should be allowed (limit %d)", i, limit)
		}
		if want := limit - i; res.Remaining != want {
			t.Fatalf("request #%d remaining = %d, want %d", i, res.Remaining, want)
		}
	}

	// The (limit+1)-th request is over budget.
	res, err := ratelimit.Allow(ctx, vk, key, limit, time.Minute)
	if err != nil {
		t.Fatalf("Allow over-limit: %v", err)
	}
	if res.Allowed {
		t.Fatalf("request #%d should be rejected (limit %d)", limit+1, limit)
	}
	if res.Remaining != 0 {
		t.Fatalf("over-limit remaining = %d, want 0", res.Remaining)
	}
}

func TestRateLimit_UnlimitedSkipsValkey(t *testing.T) {
	vk := newTestValkey(t)
	ctx := context.Background()
	key := uniqueKey(t)

	for i := 0; i < 100; i++ {
		res, err := ratelimit.Allow(ctx, vk, key, 0, time.Minute)
		if err != nil {
			t.Fatalf("Allow unlimited: %v", err)
		}
		if !res.Allowed {
			t.Fatalf("limit 0 must be unlimited")
		}
	}
	// Unlimited must not have created a counter.
	n, err := vk.Do(ctx, vk.B().Exists().Key(key).Build()).ToInt64()
	if err != nil {
		t.Fatalf("EXISTS: %v", err)
	}
	if n != 0 {
		t.Fatalf("unlimited Allow should not touch Valkey, but key exists")
	}
}

func TestRateLimit_WindowResets(t *testing.T) {
	vk := newTestValkey(t)
	ctx := context.Background()
	key := uniqueKey(t)
	const limit = 2
	window := time.Second

	for i := 1; i <= limit; i++ {
		if res, err := ratelimit.Allow(ctx, vk, key, limit, window); err != nil || !res.Allowed {
			t.Fatalf("request #%d should be allowed (err=%v)", i, err)
		}
	}
	if res, err := ratelimit.Allow(ctx, vk, key, limit, window); err != nil || res.Allowed {
		t.Fatalf("request over limit should be rejected before window reset (err=%v)", err)
	}

	// Let the window lapse, then the budget refills.
	time.Sleep(window + 300*time.Millisecond)

	res, err := ratelimit.Allow(ctx, vk, key, limit, window)
	if err != nil {
		t.Fatalf("Allow after reset: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("request should be allowed after the window resets")
	}
}

func TestRetryAfter_WithinWindow(t *testing.T) {
	vk := newTestValkey(t)
	ctx := context.Background()
	key := uniqueKey(t)
	window := time.Minute

	if _, err := ratelimit.Allow(ctx, vk, key, 1, window); err != nil {
		t.Fatalf("seed Allow: %v", err)
	}
	d := ratelimit.RetryAfter(ctx, vk, key, window)
	if d < time.Second || d > window {
		t.Fatalf("RetryAfter = %v, want [1s, %v] (floored at 1s for header consistency)", d, window)
	}
}
