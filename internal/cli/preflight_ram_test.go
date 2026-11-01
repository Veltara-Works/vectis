package cli

import "testing"

// A VPS sold as 4 GB shows the kernel ~3.8 GiB and a 2 GB one ~1.9 GiB; both
// must grade as the plan they are, not a step below (seen on a 4 GB BinaryLane
// VPS: MemTotal 4009888 kB read as "3 GB", warn).
func TestRAMResult(t *testing.T) {
	for _, tc := range []struct {
		kb         int64
		wantStatus string
		wantValue  string
	}{
		{4009888, "pass", "3.8 GB"}, // 4 GB plan (observed)
		{8048112, "pass", "7.7 GB"},
		{3670016, "pass", "3.5 GB"}, // exactly 3584 MiB
		{3500000, "warn", "3.3 GB"},
		{1990000, "warn", "1.9 GB"}, // 2 GB plan
		{1835008, "warn", "1.8 GB"}, // exactly 1792 MiB
		{1048576, "fail", "1.0 GB"},
	} {
		got := ramResult(tc.kb)
		if got.Status != tc.wantStatus || got.Value != tc.wantValue {
			t.Errorf("ramResult(%d) = %s %q, want %s %q", tc.kb, got.Status, got.Value, tc.wantStatus, tc.wantValue)
		}
	}
}
