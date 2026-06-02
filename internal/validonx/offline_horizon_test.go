package validonx

import (
	"testing"
	"time"
)

// TestOfflineHorizonPassed pins the offline-tolerance rule agreed with
// ValidonX on 2026-06-01: while ValidonX is unreachable, a stale cache may
// keep serving Pro only until the license horizon — grace_period_ends_at when
// set (past_due dunning / cancel-at-period-end), otherwise expires_at (the
// paid-through date). A nil horizon = perpetual license, no bound. This
// closes the prior gap where a healthy active sub (grace==nil) was served
// indefinitely offline regardless of its paid period.
func TestOfflineHorizonPassed(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-1 * time.Hour)
	future := now.Add(1 * time.Hour)
	tp := func(tm time.Time) *time.Time { return &tm }

	cases := []struct {
		name    string
		expires *time.Time
		grace   *time.Time
		want    bool // true = past horizon → must stop serving Pro offline
	}{
		{"healthy active, within paid period", tp(future), nil, false},
		{"healthy active, paid period elapsed (the fix)", tp(past), nil, true},
		{"past_due, within dunning grace", tp(past), tp(future), false},
		{"past_due, dunning grace elapsed", tp(past), tp(past), true},
		{"cancel-at-period-end, before period end", tp(future), tp(future), false},
		{"cancel-at-period-end, after period end", tp(past), tp(past), true},
		{"perpetual license (no expiry)", nil, nil, false},
		{"grace set, expiry nil, grace future", nil, tp(future), false},
		{"grace set, expiry nil, grace past", nil, tp(past), true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ld := LicenseResponse{ExpiresAt: tc.expires, GracePeriodEndsAt: tc.grace}
			if got := offlineHorizonPassed(ld, now); got != tc.want {
				t.Errorf("offlineHorizonPassed(expires=%v, grace=%v) = %v, want %v",
					tc.expires, tc.grace, got, tc.want)
			}
		})
	}
}
