package backup

import (
	"testing"
	"time"
)

func TestSettingsValidate(t *testing.T) {
	tests := []struct {
		name    string
		s       Settings
		wantErr bool
	}{
		{"valid daily", Settings{Schedule: "0 2 * * *", RetainDays: 30}, false},
		{"valid with tz", Settings{Schedule: "0 2 * * *", Timezone: "Australia/Sydney", RetainDays: 7}, false},
		{"empty schedule", Settings{Schedule: "  ", RetainDays: 30}, true},
		{"bad cron", Settings{Schedule: "not a cron", RetainDays: 30}, true},
		{"bad timezone", Settings{Schedule: "0 2 * * *", Timezone: "Mars/Olympus", RetainDays: 30}, true},
		{"negative retain", Settings{Schedule: "0 2 * * *", RetainDays: -1}, true},
		{"zero retain ok (keep all)", Settings{Schedule: "0 2 * * *", RetainDays: 0}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.s.Validate()
			if tc.wantErr && err == nil {
				t.Errorf("Validate() = nil, want error")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() = %v, want nil", err)
			}
		})
	}
}

// TestNextScheduledRunTimezone verifies the CRON_TZ prefix is honoured: the
// same wall-clock schedule resolves to different UTC instants depending on the
// configured timezone — this is the UTC→local fix the feature exists for.
func TestNextScheduledRunTimezone(t *testing.T) {
	// 30 May 2026 12:00 UTC. "0 2 * * *" fires daily at 02:00.
	from := time.Date(2026, 5, 30, 12, 0, 0, 0, time.UTC)

	t.Run("UTC (empty tz)", func(t *testing.T) {
		next, err := NextScheduledRun("0 2 * * *", "", from)
		if err != nil {
			t.Fatal(err)
		}
		want := time.Date(2026, 5, 31, 2, 0, 0, 0, time.UTC)
		if !next.Equal(want) {
			t.Errorf("next = %v, want %v", next.UTC(), want)
		}
	})

	t.Run("Australia/Sydney shifts the UTC instant", func(t *testing.T) {
		next, err := NextScheduledRun("0 2 * * *", "Australia/Sydney", from)
		if err != nil {
			t.Fatal(err)
		}
		loc, err := time.LoadLocation("Australia/Sydney")
		if err != nil {
			t.Skipf("tz database unavailable: %v", err)
		}
		want := time.Date(2026, 5, 31, 2, 0, 0, 0, loc) // 02:00 Sydney
		if !next.Equal(want) {
			t.Errorf("next = %v (%v UTC), want 02:00 Sydney", next, next.UTC())
		}
		// It must differ from the UTC interpretation, else the tz was ignored.
		utcNext, _ := NextScheduledRun("0 2 * * *", "", from)
		if next.Equal(utcNext) {
			t.Errorf("Sydney schedule equals UTC schedule (%v); timezone not applied", next)
		}
	})

	t.Run("invalid timezone errors", func(t *testing.T) {
		if _, err := NextScheduledRun("0 2 * * *", "Mars/Olympus", from); err == nil {
			t.Error("expected error for invalid timezone")
		}
	})
}
