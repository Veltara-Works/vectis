package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// staleLegacyLua mirrors the v0.1.1 buggy `v ~= nil` membership check that
// caused every rspamd verdict to come back `reject` until v0.1.4 hot-fixed it.
// Prod boxes that were installed pre-v0.1.4 still carry this on disk because
// nothing ever rewrote /var/vectis/generated/rspamd/local.lua post-Apply.
const staleLegacyLua = `-- Vectis spam policy (legacy v0.1.1 — buggy)
local function in_set(set, key)
  local v = set[key]
  if v ~= nil then return true end
  return false
end
`

const correctLua = `-- Vectis spam policy (v0.1.5+ — correct)
local function in_set(set, key)
  if set[key] then return true end
  return false
end
`

const newSpamMapsConf = `# Generated rspamd spam_maps.conf — new in v0.1.5
multimap "blocked_emails" { type = "from"; map = "/var/lib/rspamd/maps/blocked_emails"; }
`

func writeTempConfigs(t *testing.T, files map[string]string) (root string) {
	t.Helper()
	root = t.TempDir()
	for rel, content := range files {
		path := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

func TestRegenerateConfigs_RewritesDriftedFile(t *testing.T) {
	genDir := writeTempConfigs(t, map[string]string{
		"rspamd/local.lua":   staleLegacyLua,
		"postfix/main.cf":    "# unchanged content\n",
		"dovecot/dovecot.conf": "# unchanged content\n",
	})
	backupDir := filepath.Join(t.TempDir(), "self-heal-2026-05-01T00-00-00-configs")

	gen := func(_ context.Context, releaseTag string) ([]ConfigFile, error) {
		if releaseTag != "v0.1.5" {
			t.Errorf("expected releaseTag=v0.1.5, got %q", releaseTag)
		}
		return []ConfigFile{
			{RelPath: "rspamd/local.lua", Content: []byte(correctLua)},
			{RelPath: "postfix/main.cf", Content: []byte("# unchanged content\n")},
			{RelPath: "dovecot/dovecot.conf", Content: []byte("# unchanged content\n")},
		}, nil
	}

	rewritten, changed, err := RegenerateConfigs(context.Background(), genDir, backupDir, "v0.1.5", gen)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rewritten {
		t.Fatal("expected rewritten=true (rspamd lua differs)")
	}
	if len(changed) != 1 || changed[0] != "rspamd/local.lua" {
		t.Errorf("expected changed=[rspamd/local.lua], got %v", changed)
	}

	// Disk now carries corrected lua.
	got, _ := os.ReadFile(filepath.Join(genDir, "rspamd/local.lua"))
	if string(got) != correctLua {
		t.Errorf("rspamd lua not rewritten:\nwant:\n%s\n\ngot:\n%s", correctLua, got)
	}

	// Backup carries the buggy original — required for restore on apply failure.
	bk, err := os.ReadFile(filepath.Join(backupDir, "rspamd/local.lua"))
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(bk) != staleLegacyLua {
		t.Errorf("backup did not preserve original buggy lua:\nwant:\n%s\n\ngot:\n%s", staleLegacyLua, bk)
	}

	// Unchanged files must not have been backed up — that would clutter the
	// snapshot dir and falsely suggest those files drifted too.
	if _, err := os.Stat(filepath.Join(backupDir, "postfix/main.cf")); !os.IsNotExist(err) {
		t.Errorf("expected unchanged postfix/main.cf to be absent from backup, got err=%v", err)
	}
}

func TestRegenerateConfigs_NewFileWrittenWithoutBackup(t *testing.T) {
	genDir := writeTempConfigs(t, map[string]string{
		"postfix/main.cf": "# stable\n",
	})
	backupDir := filepath.Join(t.TempDir(), "configs-backup")

	gen := func(_ context.Context, _ string) ([]ConfigFile, error) {
		return []ConfigFile{
			{RelPath: "postfix/main.cf", Content: []byte("# stable\n")},
			// New file, never on disk before — typical case for a service
			// whose templates were added in a later release (e.g. spam maps in v0.1.5).
			{RelPath: "rspamd/spam_maps.conf", Content: []byte(newSpamMapsConf)},
		}, nil
	}

	rewritten, changed, err := RegenerateConfigs(context.Background(), genDir, backupDir, "v0.1.5", gen)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rewritten {
		t.Fatal("expected rewritten=true (new file appeared)")
	}
	if len(changed) != 1 || changed[0] != "rspamd/spam_maps.conf" {
		t.Errorf("expected changed=[rspamd/spam_maps.conf], got %v", changed)
	}

	got, _ := os.ReadFile(filepath.Join(genDir, "rspamd/spam_maps.conf"))
	if string(got) != newSpamMapsConf {
		t.Errorf("new spam_maps.conf not written")
	}

	// New files have no pre-existing on-disk content to back up. Backup dir
	// must NOT have a stub for the new file — restore relies on createdNewFiles
	// to delete it instead.
	if _, err := os.Stat(filepath.Join(backupDir, "rspamd/spam_maps.conf")); !os.IsNotExist(err) {
		t.Errorf("new file must not have backup entry, got err=%v", err)
	}
}

func TestRegenerateConfigs_NoOpWhenContentMatches(t *testing.T) {
	genDir := writeTempConfigs(t, map[string]string{
		"postfix/main.cf": "# stable\n",
	})
	backupDir := filepath.Join(t.TempDir(), "configs-backup")

	gen := func(_ context.Context, _ string) ([]ConfigFile, error) {
		return []ConfigFile{
			{RelPath: "postfix/main.cf", Content: []byte("# stable\n")},
		}, nil
	}

	rewritten, changed, err := RegenerateConfigs(context.Background(), genDir, backupDir, "v0.1.5", gen)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rewritten {
		t.Errorf("expected rewritten=false on identical content")
	}
	if len(changed) != 0 {
		t.Errorf("expected no changed files, got %v", changed)
	}
	// No backup directory should be created for a no-op pass.
	if _, err := os.Stat(backupDir); !os.IsNotExist(err) {
		t.Errorf("backup dir created on no-op: err=%v", err)
	}
}

func TestRegenerateConfigs_NilGeneratorErrors(t *testing.T) {
	_, _, err := RegenerateConfigs(context.Background(), t.TempDir(), t.TempDir(), "v0.1.5", nil)
	if err == nil {
		t.Fatal("expected error when generator is nil")
	}
}

func TestRegenerateConfigs_RejectsComposeInPayload(t *testing.T) {
	gen := func(_ context.Context, _ string) ([]ConfigFile, error) {
		return []ConfigFile{
			// The compose generator owns docker-compose.yml; the config
			// generator must not also produce it (would write to wrong path
			// or clobber the compose-write that owns versioning logic).
			{RelPath: "docker-compose.yml", Content: []byte("services: {}\n")},
		}, nil
	}
	_, _, err := RegenerateConfigs(context.Background(), t.TempDir(), t.TempDir(), "v0.1.5", gen)
	if err == nil {
		t.Fatal("expected RegenerateConfigs to reject docker-compose.yml in its payload")
	}
}

func TestRegenerateConfigs_GeneratorErrorPropagates(t *testing.T) {
	want := errors.New("template render exploded")
	gen := func(_ context.Context, _ string) ([]ConfigFile, error) {
		return nil, want
	}
	_, _, err := RegenerateConfigs(context.Background(), t.TempDir(), t.TempDir(), "v0.1.5", gen)
	if err == nil || !contains(err.Error(), want.Error()) {
		t.Fatalf("expected error containing %q, got %v", want, err)
	}
}

func TestRestoreConfigsBackup_RestoresChangedAndDeletesNew(t *testing.T) {
	genDir := writeTempConfigs(t, map[string]string{
		// Post-regen state: lua has the new (correct) content, spam_maps.conf
		// is brand-new on disk.
		"rspamd/local.lua":      correctLua,
		"rspamd/spam_maps.conf": newSpamMapsConf,
	})
	backupDir := writeTempConfigs(t, map[string]string{
		// Pre-regen state: lua had the buggy original. spam_maps.conf has
		// no backup entry because it was a brand-new write.
		"rspamd/local.lua": staleLegacyLua,
	})

	if err := RestoreConfigsBackup(genDir, backupDir, []string{"rspamd/spam_maps.conf"}); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Modified file is back to its pre-regen content.
	got, _ := os.ReadFile(filepath.Join(genDir, "rspamd/local.lua"))
	if string(got) != staleLegacyLua {
		t.Errorf("expected lua restored to pre-regen content, got:\n%s", got)
	}

	// New file was deleted — the disk truly returned to pre-regen state.
	if _, err := os.Stat(filepath.Join(genDir, "rspamd/spam_maps.conf")); !os.IsNotExist(err) {
		t.Errorf("expected new file to be removed by restore, err=%v", err)
	}
}

func TestRestoreConfigsBackup_MissingBackupDirIsNoOp(t *testing.T) {
	genDir := writeTempConfigs(t, map[string]string{
		"postfix/main.cf": "# stable\n",
	})
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	if err := RestoreConfigsBackup(genDir, missing, nil); err != nil {
		t.Fatalf("expected nil on missing backup dir, got %v", err)
	}
}

// TestRegenerateConfigs_LegacyProdLayoutFixture mirrors the actual prod drift
// captured in project_prod_compose_drift_v0.1.5_blocker.md: stale rspamd lua,
// missing spam_maps file, and a config-fragment that needs structural changes.
// Verifies the full-set regen handles the multi-file drift in one pass without
// touching truly-unchanged files.
func TestRegenerateConfigs_LegacyProdLayoutFixture(t *testing.T) {
	genDir := writeTempConfigs(t, map[string]string{
		// Drifted: pre-v0.1.4 buggy lua.
		"rspamd/local.lua": staleLegacyLua,
		// Drifted: structural — different paths from current templates.
		"traefik/traefik.yml": `# Legacy traefik — points at acme-sh sidecar location.
certificatesResolvers:
  letsencrypt:
    acme:
      storage: /etc/traefik/acme/acme.json
`,
		// Unchanged.
		"postfix/main.cf": "# stable since v0.1.0\n",
	})
	backupDir := filepath.Join(t.TempDir(), "configs-backup")

	wantTraefik := `# Current traefik — extracted certs from cert-extractor sidecar.
certificatesResolvers:
  letsencrypt:
    acme:
      storage: /var/traefik/acme/acme.json
`
	gen := func(_ context.Context, _ string) ([]ConfigFile, error) {
		return []ConfigFile{
			{RelPath: "rspamd/local.lua", Content: []byte(correctLua)},
			{RelPath: "rspamd/spam_maps.conf", Content: []byte(newSpamMapsConf)},
			{RelPath: "traefik/traefik.yml", Content: []byte(wantTraefik)},
			{RelPath: "postfix/main.cf", Content: []byte("# stable since v0.1.0\n")},
		}, nil
	}

	rewritten, changed, err := RegenerateConfigs(context.Background(), genDir, backupDir, "v0.1.5", gen)
	if err != nil {
		t.Fatalf("regen: %v", err)
	}
	if !rewritten {
		t.Fatal("expected rewritten=true on legacy-layout fixture")
	}

	sort.Strings(changed)
	want := []string{"rspamd/local.lua", "rspamd/spam_maps.conf", "traefik/traefik.yml"}
	if !equalStringSlices(changed, want) {
		t.Errorf("changed files: want %v, got %v", want, changed)
	}

	// Verify each disk write landed correctly.
	cases := map[string]string{
		"rspamd/local.lua":      correctLua,
		"rspamd/spam_maps.conf": newSpamMapsConf,
		"traefik/traefik.yml":   wantTraefik,
		"postfix/main.cf":       "# stable since v0.1.0\n", // unchanged
	}
	for rel, want := range cases {
		got, err := os.ReadFile(filepath.Join(genDir, rel))
		if err != nil {
			t.Errorf("read %s: %v", rel, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s mismatch:\nwant:\n%s\n\ngot:\n%s", rel, want, got)
		}
	}

	// Backup must hold the OLD content of files that existed pre-regen, and
	// must NOT hold a stub for the brand-new spam_maps.conf.
	bkLua, _ := os.ReadFile(filepath.Join(backupDir, "rspamd/local.lua"))
	if string(bkLua) != staleLegacyLua {
		t.Errorf("backup lua not preserved")
	}
	if _, err := os.Stat(filepath.Join(backupDir, "rspamd/spam_maps.conf")); !os.IsNotExist(err) {
		t.Errorf("spam_maps.conf must not be in backup (was brand-new), err=%v", err)
	}
}

func contains(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
