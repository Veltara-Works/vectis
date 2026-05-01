package orchestrator

import "testing"

func TestDecideSelfHealAction(t *testing.T) {
	tests := []struct {
		name       string
		prev       string
		current    string
		hasGen     bool
		hasPath    bool
		want       selfHealAction
		wantReason string
	}{
		{
			name: "dev binary skips entirely",
			prev: "v0.1.0", current: "dev", hasGen: true, hasPath: true,
			want: selfHealSkip, wantReason: "dev versions never trigger self-heal — local workflows must not be surprised",
		},
		{
			name: "empty binary version skips",
			prev: "v0.1.0", current: "", hasGen: true, hasPath: true,
			want: selfHealSkip, wantReason: "version unset (likely missing -ldflags) is not a real release",
		},
		{
			name: "no compose generator wired skips",
			prev: "v0.1.0", current: "v0.1.3", hasGen: false, hasPath: true,
			want: selfHealSkip, wantReason: "without a generator we cannot regen — silently skip",
		},
		{
			name: "no compose path configured skips",
			prev: "v0.1.0", current: "v0.1.3", hasGen: true, hasPath: false,
			want: selfHealSkip, wantReason: "no path means nothing to write to",
		},
		{
			name: "fresh install (empty prev) baselines",
			prev: "", current: "v0.1.3", hasGen: true, hasPath: true,
			want: selfHealBaseline, wantReason: "first boot — record version but don't heal; on-disk compose is authoritative on install",
		},
		{
			name: "same-version reboot is steady state",
			prev: "v0.1.3", current: "v0.1.3", hasGen: true, hasPath: true,
			want: selfHealSkip, wantReason: "no version transition — steady state",
		},
		{
			name: "version transition triggers reconcile",
			prev: "v0.1.0", current: "v0.1.3", hasGen: true, hasPath: true,
			want: selfHealReconcile, wantReason: "this is the cross-version Apply gap §10 self-heal closes",
		},
		{
			name: "rc to stable transition triggers reconcile",
			prev: "v0.1.3-rc1", current: "v0.1.3", hasGen: true, hasPath: true,
			want: selfHealReconcile, wantReason: "any version string difference counts as transition",
		},
		{
			name: "downgrade still triggers reconcile",
			prev: "v0.1.3", current: "v0.1.2", hasGen: true, hasPath: true,
			want: selfHealReconcile, wantReason: "operator-driven downgrade also benefits from reconcile (rare but possible)",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := decideSelfHealAction(tc.prev, tc.current, tc.hasGen, tc.hasPath)
			if got != tc.want {
				t.Errorf("decideSelfHealAction(prev=%q, cur=%q, gen=%v, path=%v) = %v, want %v\n  reason: %s",
					tc.prev, tc.current, tc.hasGen, tc.hasPath, got, tc.want, tc.wantReason)
			}
		})
	}
}
