package backup

import (
	"archive/tar"
	"context"
	"errors"
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

// F-R1: a truncated/corrupt archive must fail the restore WITHOUT destroying the
// live target. Restore is exactly the moment the operator is already in trouble,
// so a restore that wipes /etc/vectis (incl. the only surviving copy of
// secrets.yaml) before the replacement is verified is a DR footgun with no
// rollback. The stage-and-swap fix leaves the live install completely untouched
// on any extract failure.
func TestRestoreDirectoryTruncatedArchiveKeepsTarget(t *testing.T) {
	root := t.TempDir()

	// A corrupt "archive": not a valid tar, so `tar -xf` fails.
	archive := filepath.Join(root, "config.tar")
	if err := os.WriteFile(archive, []byte("this is not a tar file\x00\x01\x02"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Live target with the operator's secrets + an existing config.
	target := filepath.Join(root, "etc", "vectis")
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "config.yaml"), []byte("version: live\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "secrets.yaml"), []byte("api:\n  secret: KEEPME\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	m := &Manager{}
	if err := m.restoreDirectory(context.Background(), archive, target, "secrets.yaml*"); err == nil {
		t.Fatal("expected restoreDirectory to fail on a corrupt archive, got nil")
	}

	// The live target and its secrets must be completely intact.
	got, err := os.ReadFile(filepath.Join(target, "secrets.yaml"))
	if err != nil {
		t.Fatalf("secrets.yaml destroyed by failed restore (F-R1 regression): %v", err)
	}
	if !strings.Contains(string(got), "KEEPME") {
		t.Errorf("secrets.yaml content changed: %q", got)
	}
	cfg, err := os.ReadFile(filepath.Join(target, "config.yaml"))
	if err != nil {
		t.Fatalf("config.yaml destroyed by failed restore: %v", err)
	}
	if !strings.Contains(string(cfg), "live") {
		t.Errorf("config.yaml should be unchanged (still 'live'), got: %q", cfg)
	}

	// No staging leftovers inside the target (staging is created inside targetDir
	// so it lands on the same filesystem, incl. a mountpoint target).
	entries, _ := os.ReadDir(target)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".vectis-restore-") {
			t.Errorf("leftover restore staging not cleaned up: %s", e.Name())
		}
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

	// The manifest entry must carry a UNIQUE id, not the non-unique
	// "no-db-create" sentinel — otherwise repeated host CLI backups collide in
	// the full→incremental chain (Copilot review, PR #3).
	manifest, err := LoadManifest(cfg.BackupDir)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	entry := manifest.LastFull()
	if entry == nil {
		t.Fatal("manifest has no full entry after Create")
	}
	if entry.ID == "no-db-create" {
		t.Errorf("manifest entry ID is the non-unique sentinel %q", entry.ID)
	}
	if entry.ID != filepath.Base(path) {
		t.Errorf("manifest entry ID = %q, want archive basename %q", entry.ID, filepath.Base(path))
	}
}

// TestDirectDBUsesTCPDumpNotDocker verifies the `vectis backup create --db-host`
// override: with cfg.DirectDB set, NewManager must route the dump through the TCP
// pg_dump path (cfg.DBHost) even with a nil pool — not the default docker-exec
// path. Pointed at an unreachable host so the dump fails fast; the error must come
// from pg_dump (TCP), never from `docker exec`. Robust whether or not pg_dump is
// installed in CI (both "not found" and "connection refused" surface as a pg_dump
// error, and neither mentions docker exec).
func TestDirectDBUsesTCPDumpNotDocker(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.BackupDir = filepath.Join(root, "backups")
	cfg.MailDataDir = filepath.Join(root, "mail")
	cfg.DKIMDir = filepath.Join(root, "dkim")
	cfg.ConfigDir = filepath.Join(root, "vectis")
	cfg.SnapshotDir = filepath.Join(root, "snapshots")
	cfg.DirectDB = true      // the --db-host override
	cfg.DBHost = "127.0.0.1" // directly-reachable host (here, nothing listening)
	cfg.DBPort = 1           // no server on port 1
	cfg.DBName = "vectis"
	cfg.DBUser = "vectis_api"
	for _, d := range []string{cfg.BackupDir, cfg.MailDataDir, cfg.DKIMDir, cfg.ConfigDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewManager(nil, logger, cfg) // nil pool, but DirectDB → TCP path

	_, _, err := mgr.Create(context.Background(), nil)
	if err == nil {
		t.Fatal("expected the dump to fail against an unreachable host")
	}
	if !strings.Contains(err.Error(), "pg_dump") {
		t.Errorf("expected a pg_dump (TCP) error, got: %v", err)
	}
	if strings.Contains(err.Error(), "docker exec") {
		t.Errorf("DirectDB must not use the docker-exec path, but error mentions it: %v", err)
	}
}

// TestIsIncrementalArchiveName covers the on-disk discriminator used to keep
// incremental archives out of the direct (full-only) restore path (BAK-1).
func TestIsIncrementalArchiveName(t *testing.T) {
	cases := []struct {
		name string
		want bool
	}{
		{"vectis-incr-20260101-000000.tar.gz", true},
		{"vectis-incr-20260101-000000.tar.gz.enc", true},
		{"/var/vectis/backups/vectis-incr-20260101-000000.tar.gz.enc", true},
		{"vectis-20260101-000000.tar.gz", false},
		{"/var/vectis/backups/vectis-20260101-000000.tar.gz.enc", false},
		{"vectis-incremental-note.tar.gz", false}, // not the -incr- prefix
		{"random.tar.gz", false},
	}
	for _, tc := range cases {
		if got := IsIncrementalArchiveName(tc.name); got != tc.want {
			t.Errorf("IsIncrementalArchiveName(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// TestRestoreRejectsIncrementalByName is the primary BAK-1 guard: Restore and
// RestoreAsync must refuse an incrementally-named archive up front, before any
// job is created or destructive step runs. Restoring an incremental via the
// full-only path clears the maildir and unpacks only the since-parent delta,
// silently destroying all older mail.
func TestRestoreRejectsIncrementalByName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewManager(nil, logger, DefaultConfig())
	incr := "/var/vectis/backups/vectis-incr-20260101-000000.tar.gz.enc"

	if err := mgr.Restore(context.Background(), incr, nil); !errors.Is(err, ErrIncrementalRestore) {
		t.Fatalf("Restore(incremental) = %v, want ErrIncrementalRestore", err)
	}
	jobID, err := mgr.RestoreAsync(context.Background(), incr, nil)
	if !errors.Is(err, ErrIncrementalRestore) {
		t.Fatalf("RestoreAsync(incremental) err = %v, want ErrIncrementalRestore", err)
	}
	if jobID != "" {
		t.Errorf("RestoreAsync(incremental) job ID = %q, want empty (no job started)", jobID)
	}
}

// TestRestoreRejectsIncrementalMarkerNonDestructive is the belt-and-suspenders
// guard for BAK-1: an incremental archive whose filename was changed off the
// vectis-incr- convention still carries the authoritative in-archive type
// marker. Restore must detect it after extraction but BEFORE clearing any data,
// leaving the live maildir completely intact.
func TestRestoreRejectsIncrementalMarkerNonDestructive(t *testing.T) {
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.BackupDir = filepath.Join(root, "backups")
	cfg.MailDataDir = filepath.Join(root, "mail")
	cfg.EncryptionKey = "" // plaintext archive keeps the round-trip simple
	for _, d := range []string{cfg.BackupDir, cfg.MailDataDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Pre-existing mail that must survive the refused restore.
	if err := os.WriteFile(filepath.Join(cfg.MailDataDir, "important.eml"), []byte("KEEPME"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Assemble an archive carrying the incremental type marker, then name the
	// final file WITHOUT the vectis-incr- prefix so it slips past the name guard.
	asm := filepath.Join(root, "asm")
	if err := os.MkdirAll(asm, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(asm, backupTypeMarkerFile), []byte(string(BackupIncremental)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	mgr := NewManager(nil, logger, cfg)
	// Fail loudly if any destructive step is reached — the marker guard must fire first.
	mgr.stopServicesFn = func(context.Context) error {
		t.Fatal("stopServices reached: marker guard failed to abort before destructive steps")
		return nil
	}
	mgr.restoreDBFn = func(context.Context, string) error {
		t.Fatal("restoreDB reached: marker guard failed to abort")
		return nil
	}

	archivePath := filepath.Join(cfg.BackupDir, "vectis-renamed-20260101-000000.tar.gz")
	if err := mgr.createFinalArchive(context.Background(), asm, archivePath); err != nil {
		t.Fatalf("createFinalArchive: %v", err)
	}

	if err := mgr.Restore(context.Background(), archivePath, nil); !errors.Is(err, ErrIncrementalRestore) {
		t.Fatalf("Restore(renamed incremental) = %v, want ErrIncrementalRestore", err)
	}

	// The live maildir and its content must be completely intact.
	got, err := os.ReadFile(filepath.Join(cfg.MailDataDir, "important.eml"))
	if err != nil {
		t.Fatalf("maildir destroyed by refused incremental restore (BAK-1 regression): %v", err)
	}
	if string(got) != "KEEPME" {
		t.Errorf("mail content changed: %q, want KEEPME", got)
	}
}
