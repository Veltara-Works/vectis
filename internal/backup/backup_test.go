package backup

import (
	"archive/tar"
	"context"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestConfigArchiveExcludesSecretsVariants guards Finding A from the 2026-05-30
// Scenario-B DR drill: the config archive must exclude secrets.yaml AND every
// renamed copy the config tooling leaves behind on cutovers (.pre-*, .bak.*),
// not just the exact filename. Each variant holds the same live credentials.
func TestConfigArchiveExcludesSecretsVariants(t *testing.T) {
	src := t.TempDir()
	cfgDir := filepath.Join(src, "vectis")
	if err := os.MkdirAll(cfgDir, 0o755); err != nil {
		t.Fatal(err)
	}

	keep := []string{"config.yaml", "docker-compose.yml"}
	drop := []string{
		"secrets.yaml",
		"secrets.yaml.pre-f3.20260530T041856Z",
		"secrets.yaml.bak.20260430",
		"secrets.yaml.pre-v0.1.17",
	}
	for _, f := range append(append([]string{}, keep...), drop...) {
		if err := os.WriteFile(filepath.Join(cfgDir, f), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	out := filepath.Join(src, "config.tar")
	m := &Manager{}
	if err := m.archiveDirectoryExcluding(context.Background(), cfgDir, out, secretsExcludeFiles); err != nil {
		t.Fatalf("archiveDirectoryExcluding: %v", err)
	}

	members := tarMemberNames(t, out)
	for _, n := range members {
		if strings.Contains(filepath.Base(n), "secrets.yaml") {
			t.Errorf("secret-bearing file leaked into backup archive: %q", n)
		}
	}
	for _, want := range keep {
		found := false
		for _, n := range members {
			if filepath.Base(n) == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q to be retained in archive; members=%v", want, members)
		}
	}
}

func tarMemberNames(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	var names []string
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, h.Name)
	}
	return names
}

// TestRestoreDirectoryPreservesSecrets guards Finding E from the 2026-05-30
// Scenario-B DR drill: restoring config.tar must NOT delete secrets.yaml.
// secrets.yaml is excluded from backups (Finding A), so the config archive
// never contains it; restoreDirectory wipes the target dir before extracting,
// which deleted operator-staged secrets.yaml and left the install unbootable.
// The fix preserves secrets.yaml* across the restore.
func TestRestoreDirectoryPreservesSecrets(t *testing.T) {
	root := t.TempDir()

	// Build a config.tar the way Create does (tar -C parent base), WITHOUT
	// secrets.yaml — mirroring a real backup.
	src := filepath.Join(root, "src", "vectis")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "config.yaml"), []byte("version: from-backup\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(root, "config.tar")
	if out, err := exec.Command("tar", "-cf", archive, "-C", filepath.Dir(src), filepath.Base(src)).CombinedOutput(); err != nil {
		t.Fatalf("build archive: %v: %s", err, out)
	}

	// Target dir already holds an operator-staged secrets.yaml + an old config.
	target := filepath.Join(root, "etc", "vectis")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "config.yaml"), []byte("version: old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "secrets.yaml"), []byte("api:\n  secret: KEEPME\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := &Manager{}
	if err := m.restoreDirectory(context.Background(), archive, target, "secrets.yaml*"); err != nil {
		t.Fatalf("restoreDirectory: %v", err)
	}

	// secrets.yaml must survive with its content + mode intact.
	got, err := os.ReadFile(filepath.Join(target, "secrets.yaml"))
	if err != nil {
		t.Fatalf("secrets.yaml deleted by restore (Finding E regression): %v", err)
	}
	if !strings.Contains(string(got), "KEEPME") {
		t.Errorf("secrets.yaml content changed: %q", got)
	}
	if fi, err := os.Stat(filepath.Join(target, "secrets.yaml")); err == nil && fi.Mode().Perm() != 0o600 {
		t.Errorf("secrets.yaml mode = %v, want 0600", fi.Mode().Perm())
	}

	// config.yaml must be the backup's version (the restore still replaces it).
	cfg, err := os.ReadFile(filepath.Join(target, "config.yaml"))
	if err != nil {
		t.Fatalf("config.yaml missing after restore: %v", err)
	}
	if !strings.Contains(string(cfg), "from-backup") {
		t.Errorf("config.yaml not restored from backup: %q", cfg)
	}
}

// TestCreateHostPathNilPool guards the Finding-B follow-up: `vectis backup create`
// runs on the host without a DB pool (the host cannot resolve the Docker-internal
// "postgres" hostname), so Create must not panic on the absent backup_jobs repo
// and must drive the DB dump through the injectable hook (the real host path is
// `docker exec pg_dump`). The hook is stubbed here so the test stays offline.
func TestCreateHostPathNilPool(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.BackupDir = filepath.Join(root, "backups")
	cfg.MailDataDir = filepath.Join(root, "mail")
	cfg.DKIMDir = filepath.Join(root, "dkim")
	cfg.ConfigDir = filepath.Join(root, "vectis")
	cfg.SnapshotDir = filepath.Join(root, "snapshots")
	cfg.EncryptionKey = "test-key-host-create" // exercise the production .enc path
	for _, d := range []string{cfg.BackupDir, cfg.MailDataDir, cfg.DKIMDir, cfg.ConfigDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cfg.ConfigDir, "config.yaml"), []byte("version: host-create\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewManager(nil, logger, cfg) // nil pool = host CLI path
	// Stub the DB dump: the real host path is `docker exec pg_dump`, unavailable in CI.
	mgr.dumpDBFn = func(_ context.Context, dst string) error {
		return os.WriteFile(dst, []byte("-- fake dump\nSELECT 1;\n"), 0o600)
	}

	path, size, err := mgr.Create(context.Background(), nil)
	if err != nil {
		t.Fatalf("Create on nil-pool host path: %v", err)
	}
	if size <= 0 {
		t.Fatalf("backup size = %d, want > 0", size)
	}
	if filepath.Ext(path) != ".enc" {
		t.Fatalf("expected encrypted archive (.enc), got %q", path)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("archive not written: %v", err)
	}
}
