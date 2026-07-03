package monitor

import (
	"testing"
	"time"
)

// TestNew_Defaults verifies that New() fills zero/negative tuning knobs with the
// documented defaults and preserves explicit values. Expected values come from
// DefaultConfig() rather than duplicated constants, so this also pins New() and
// DefaultConfig() to the same defaults. The db/vk handles are only stored (not
// dialled) by New, so nil is safe here.
func TestNew_Defaults(t *testing.T) {
	def := DefaultConfig()

	t.Run("zero config gets defaults", func(t *testing.T) {
		m := New(nil, nil, nil, Config{}, mustLogger())
		if m.cfg.CheckInterval != def.CheckInterval {
			t.Errorf("CheckInterval = %v, want %v", m.cfg.CheckInterval, def.CheckInterval)
		}
		if m.cfg.DiskWarnPercent != def.DiskWarnPercent {
			t.Errorf("DiskWarnPercent = %d, want %d", m.cfg.DiskWarnPercent, def.DiskWarnPercent)
		}
		if m.cfg.QueueWarnSize != def.QueueWarnSize {
			t.Errorf("QueueWarnSize = %d, want %d", m.cfg.QueueWarnSize, def.QueueWarnSize)
		}
		if m.cfg.CertWarnDays != def.CertWarnDays {
			t.Errorf("CertWarnDays = %d, want %d", m.cfg.CertWarnDays, def.CertWarnDays)
		}
	})

	t.Run("negative values get defaults", func(t *testing.T) {
		m := New(nil, nil, nil, Config{
			CheckInterval:   -1,
			DiskWarnPercent: -5,
			QueueWarnSize:   -5,
			CertWarnDays:    -5,
		}, mustLogger())
		if m.cfg.CheckInterval != def.CheckInterval || m.cfg.DiskWarnPercent != def.DiskWarnPercent ||
			m.cfg.QueueWarnSize != def.QueueWarnSize || m.cfg.CertWarnDays != def.CertWarnDays {
			t.Errorf("negative config not defaulted: %+v", m.cfg)
		}
	})

	t.Run("explicit values preserved", func(t *testing.T) {
		m := New(nil, nil, nil, Config{
			CheckInterval:   30 * time.Second,
			DiskWarnPercent: 90,
			QueueWarnSize:   250,
			CertWarnDays:    7,
		}, mustLogger())
		if m.cfg.CheckInterval != 30*time.Second {
			t.Errorf("CheckInterval = %v, want 30s", m.cfg.CheckInterval)
		}
		if m.cfg.DiskWarnPercent != 90 || m.cfg.QueueWarnSize != 250 || m.cfg.CertWarnDays != 7 {
			t.Errorf("explicit config not preserved: %+v", m.cfg)
		}
	})
}

// TestParseDfPercent covers the `df --output=pcent` parser, including the
// trailing-% trim, multi-line input, and the malformed/short-input guards.
func TestParseDfPercent(t *testing.T) {
	tests := []struct {
		name    string
		out     string
		want    int
		wantErr bool
	}{
		{"typical output", "Use%\n 42%\n", 42, false},
		{"full disk", "Use%\n100%\n", 100, false},
		{"zero usage", "Use%\n  0%\n", 0, false},
		{"no whitespace", "Use%\n7%", 7, false},
		{"missing data line", "Use%\n", 0, true},
		{"empty", "", 0, true},
		{"non-numeric", "Use%\nN/A%\n", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseDfPercent([]byte(tt.out))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseDfPercent(%q) err = %v, wantErr = %v", tt.out, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parseDfPercent(%q) = %d, want %d", tt.out, got, tt.want)
			}
		})
	}
}

// TestParsePostqueueCount covers the `postqueue -p` parser: the empty-queue
// sentinel, the trailing "in <count> Requests." summary line, and the
// hex-prefix line-count fallback.
func TestParsePostqueueCount(t *testing.T) {
	const summary = `-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
A1B2C3D4E5  1234 Tue Jun 16 21:00:00  sender@example.com
                                       rcpt@example.com

-- 42 Kbytes in 15 Requests.`

	const hexFallback = `-Queue ID-  --Size-- ----Arrival Time---- -Sender/Recipient-------
A1B2C3D4E5  1234 Tue Jun 16 21:00:00  sender@example.com
                                       rcpt@example.com
F6E5D4C3B2  5678 Tue Jun 16 21:01:00  sender2@example.com
                                       rcpt2@example.com`

	tests := []struct {
		name    string
		out     string
		want    int
		wantErr bool
	}{
		{"empty queue sentinel", "Mail queue is empty", 0, false},
		{"summary line wins", summary, 15, false},
		{"hex-prefix fallback", hexFallback, 2, false},
		{"single entry no summary", "A1B2C3D4E5  1234 Tue Jun 16 21:00:00  s@e.com", 1, false},
		{"unparseable count in summary", "-- 1 Kbytes in NaN Requests.", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePostqueueCount([]byte(tt.out))
			if (err != nil) != tt.wantErr {
				t.Fatalf("parsePostqueueCount(%q) err = %v, wantErr = %v", tt.out, err, tt.wantErr)
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("parsePostqueueCount() = %d, want %d", got, tt.want)
			}
		})
	}
}

// TestIsHexPrefix covers the hex-digit first-character check used to identify
// Postfix queue-entry lines.
func TestIsHexPrefix(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"A1B2C3D4", true},
		{"f6e5d4c3", true},
		{"0abc", true},
		{"9zzz", true},
		{"-- summary", false},
		{"ghijk", false},
		{" leading space", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := isHexPrefix(tt.in); got != tt.want {
				t.Errorf("isHexPrefix(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestEvalBackupAge pins the pure backup-age decision (C-1): none-on-record,
// fresh, exactly-at-grace, and past-grace. Grace factor is 1.5x the interval.
func TestEvalBackupAge(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	daily := 24 * time.Hour // threshold = 36h

	t.Run("nil is never", func(t *testing.T) {
		if got := evalBackupAge(nil, now, daily); got != backupAgeNever {
			t.Errorf("evalBackupAge(nil) = %v, want backupAgeNever", got)
		}
	})

	t.Run("recent is ok", func(t *testing.T) {
		last := now.Add(-2 * time.Hour)
		if got := evalBackupAge(&last, now, daily); got != backupAgeOK {
			t.Errorf("evalBackupAge(2h ago) = %v, want backupAgeOK", got)
		}
	})

	t.Run("just under grace is ok", func(t *testing.T) {
		last := now.Add(-35 * time.Hour) // < 36h threshold
		if got := evalBackupAge(&last, now, daily); got != backupAgeOK {
			t.Errorf("evalBackupAge(35h ago) = %v, want backupAgeOK", got)
		}
	})

	t.Run("past grace is stale", func(t *testing.T) {
		last := now.Add(-37 * time.Hour) // > 36h threshold
		if got := evalBackupAge(&last, now, daily); got != backupAgeStale {
			t.Errorf("evalBackupAge(37h ago) = %v, want backupAgeStale", got)
		}
	})

	t.Run("weekend-wide interval tolerates the gap", func(t *testing.T) {
		// Weekday-only cron: expected interval 72h, threshold 108h. A backup 80h
		// old (over a weekend) is still healthy.
		last := now.Add(-80 * time.Hour)
		if got := evalBackupAge(&last, now, 72*time.Hour); got != backupAgeOK {
			t.Errorf("evalBackupAge(80h ago, 72h interval) = %v, want backupAgeOK", got)
		}
	})
}
