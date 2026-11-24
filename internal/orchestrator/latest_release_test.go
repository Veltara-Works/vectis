package orchestrator

import (
	"testing"
	"time"
)

func TestLatestFromManifest(t *testing.T) {
	now := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	rel := time.Date(2026, 11, 24, 6, 55, 0, 0, time.UTC)
	cases := []struct {
		name, current, latest string
		want                  bool
	}{
		{"newer patch", "v0.1.65", "v0.1.66", true},
		{"same", "v0.1.66", "v0.1.66", false},
		{"rc of the running version is older than the stable", "v0.1.66", "v0.1.66-rc1", false},
		{"stable after the rc we run", "v0.1.66-rc1", "v0.1.66", true},
		{"newer minor", "v0.1.66", "v0.2.0", true},
		{"dev build never claims an update", "dev", "v0.1.66", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lr, err := latestFromManifest(&ReleaseManifest{Latest: tc.latest, Channel: "stable", ReleasedAt: rel}, tc.current, now)
			if err != nil {
				t.Fatal(err)
			}
			if lr.UpdateAvailable != tc.want {
				t.Errorf("UpdateAvailable = %v, want %v", lr.UpdateAvailable, tc.want)
			}
			if lr.Current != tc.current || lr.Latest != tc.latest || lr.Channel != "stable" || !lr.ReleasedAt.Equal(rel) || !lr.CheckedAt.Equal(now) {
				t.Errorf("fields = %+v", lr)
			}
		})
	}
}
