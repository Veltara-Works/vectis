package monitor

import (
	"testing"
	"time"
)

// TestNew_Defaults verifies that New() fills zero/negative tuning knobs with the
// documented defaults and preserves explicit values. The db/vk handles are only
// stored (not dialled) by New, so nil is safe here.
func TestNew_Defaults(t *testing.T) {
	t.Run("zero config gets defaults", func(t *testing.T) {
		m := New(nil, nil, nil, Config{}, mustLogger())
		if m.cfg.CheckInterval != 60*time.Second {
			t.Errorf("CheckInterval = %v, want 60s", m.cfg.CheckInterval)
		}
		if m.cfg.DiskWarnPercent != 80 {
			t.Errorf("DiskWarnPercent = %d, want 80", m.cfg.DiskWarnPercent)
		}
		if m.cfg.QueueWarnSize != 100 {
			t.Errorf("QueueWarnSize = %d, want 100", m.cfg.QueueWarnSize)
		}
		if m.cfg.CertWarnDays != 14 {
			t.Errorf("CertWarnDays = %d, want 14", m.cfg.CertWarnDays)
		}
	})

	t.Run("negative values get defaults", func(t *testing.T) {
		m := New(nil, nil, nil, Config{
			CheckInterval:   -1,
			DiskWarnPercent: -5,
			QueueWarnSize:   -5,
			CertWarnDays:    -5,
		}, mustLogger())
		if m.cfg.CheckInterval != 60*time.Second || m.cfg.DiskWarnPercent != 80 ||
			m.cfg.QueueWarnSize != 100 || m.cfg.CertWarnDays != 14 {
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
