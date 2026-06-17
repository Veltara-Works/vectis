package orchestrator

import (
	"reflect"
	"testing"
)

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
			name: "empty prev triggers reconcile (covers upgrade-from-pre-self-heal-version path)",
			prev: "", current: "v0.1.3", hasGen: true, hasPath: true,
			want: selfHealReconcile, wantReason: "old orchestrator (v0.1.0/v0.1.1/v0.1.2) never wrote last-seen-version; new orchestrator must reconcile. Genuinely-fresh installs are safe because RegenerateCompose is no-op when on-disk == templates.",
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

func TestContainerNamesForConfigPaths(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  []string
	}{
		{
			name:  "single postfix file maps to vectis-postfix",
			paths: []string{"postfix/main.cf"},
			want:  []string{"vectis-postfix"},
		},
		{
			name:  "multiple files in same service deduplicate",
			paths: []string{"rspamd/maps/allow.map", "rspamd/maps/block.map", "rspamd/local.d/options.inc"},
			want:  []string{"vectis-rspamd"},
		},
		{
			name:  "mixed services produce sorted list",
			paths: []string{"postfix/main.cf", "dovecot/dovecot.conf", "rspamd/maps/allow.map"},
			want:  []string{"vectis-dovecot", "vectis-postfix", "vectis-rspamd"},
		},
		{
			name:  "orchestrator never restarts itself",
			paths: []string{"orchestrator/whatever.conf"},
			want:  []string{},
		},
		{
			name:  "data services excluded (not in VectisImageServices)",
			paths: []string{"postgres/init-users.sh"},
			want:  []string{},
		},
		{
			name:  "unknown first segment dropped silently",
			paths: []string{"unknown-service/foo.conf", "postfix/main.cf"},
			want:  []string{"vectis-postfix"},
		},
		{
			name:  "empty + malformed paths skipped",
			paths: []string{"", "no-slash", "/leading-slash"},
			want:  []string{},
		},
		{
			name:  "empty input returns empty",
			paths: nil,
			want:  []string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := containerNamesForConfigPaths(tc.paths)
			// Normalise empty slice vs nil for compare.
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("containerNamesForConfigPaths(%v) = %v, want %v", tc.paths, got, tc.want)
			}
		})
	}
}

func TestServicesForConfigPaths(t *testing.T) {
	// Same filtering as containerNamesForConfigPaths but returns service names
	// (no vectis- prefix), and the container version must stay derivable from it.
	got := servicesForConfigPaths([]string{"postfix/main.cf", "webmail/nginx.conf", "orchestrator/x.conf", "postgres/init.sh"})
	want := []string{"postfix", "webmail"} // orchestrator + data services dropped, sorted
	if !reflect.DeepEqual(got, want) {
		t.Errorf("servicesForConfigPaths = %v, want %v", got, want)
	}
}

func TestConfigRestartTargets(t *testing.T) {
	tests := []struct {
		name           string
		configsChanged []string
		imageBumped    map[string]bool
		want           []string
	}{
		{
			name:           "config-only services restart; image-bumped excluded",
			configsChanged: []string{"postfix/main.cf", "webmail/nginx.conf", "cert-extractor/run.sh"},
			imageBumped:    map[string]bool{"postfix": true}, // postfix recreated by the bump already
			want:           []string{"cert-extractor", "webmail"},
		},
		{
			name:           "all changed services were image-bumped → nothing extra to restart",
			configsChanged: []string{"rspamd/local.d/options.inc", "dovecot/dovecot.conf"},
			imageBumped:    map[string]bool{"rspamd": true, "dovecot": true},
			want:           []string{},
		},
		{
			name:           "no image bumps → every config-changed service restarts",
			configsChanged: []string{"webmail/nginx.conf", "postfix/main.cf"},
			imageBumped:    map[string]bool{},
			want:           []string{"postfix", "webmail"},
		},
		{
			name:           "orchestrator + data services never targeted even if changed",
			configsChanged: []string{"orchestrator/x.conf", "postgres/init.sh", "valkey/valkey.conf"},
			imageBumped:    nil,
			want:           []string{},
		},
		{
			name:           "no config changes → empty",
			configsChanged: nil,
			imageBumped:    map[string]bool{"postfix": true},
			want:           []string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := configRestartTargets(tc.configsChanged, tc.imageBumped)
			if len(got) == 0 && len(tc.want) == 0 {
				return
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("configRestartTargets(%v, %v) = %v, want %v", tc.configsChanged, tc.imageBumped, got, tc.want)
			}
		})
	}
}
