//go:build integration

package backup

// Backup -> disaster -> restore round-trip against a real Postgres. This is
// the P8-H3 "backup/restore CI lane": it proves the documented disaster-
// recovery path actually round-trips data, not just that the code compiles.
//
// It exercises the real Manager.Create / Manager.Restore (pg_dump + psql +
// tar + AES-256-GCM encryption), only stubbing out the docker-compose
// service control — CI has no compose stack to stop/start, and that step is
// orchestration, not data integrity.
//
// Requires: a reachable Postgres (defaults match the CI service container)
// and pg_dump/psql whose version is >= the server (17). Run with:
//   go test -tags integration ./internal/backup/ -run TestBackupRestore -v

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestBackupRestoreRoundTrip(t *testing.T) {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
	defer cancel()

	dbCfg := database.Config{
		Host:     envOr("VECTIS_TEST_PG_HOST", "127.0.0.1"),
		Port:     envOrInt("VECTIS_TEST_PG_PORT", 5432),
		Name:     envOr("VECTIS_TEST_PG_DB", "vectis"),
		User:     envOr("VECTIS_TEST_PG_USER", "postgres"),
		Password: envOr("VECTIS_TEST_PG_PASSWORD", "vectis_dev_super"),
	}
	pool, err := database.NewPool(ctx, dbCfg, logger)
	if err != nil {
		t.Fatalf("connect postgres: %v", err)
	}
	defer pool.Close()

	// Migrations give the dump a realistic schema (and the backup_jobs table
	// the Manager writes its job records into).
	if err := database.RunMigrations(dbCfg.DSN(), logger); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	// Canary row in a dedicated table — an unambiguous assertion that survives
	// schema churn elsewhere.
	token := "dr-canary-" + strconv.FormatInt(time.Now().UnixNano(), 10)
	mustExec(ctx, t, pool, `CREATE TABLE IF NOT EXISTS dr_canary (token text PRIMARY KEY)`)
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = pool.Exec(c, `DROP TABLE IF EXISTS dr_canary`)
	})
	mustExec(ctx, t, pool, `INSERT INTO dr_canary (token) VALUES ($1)`, token)

	// Temp trees standing in for the on-host backup/data/config/dkim dirs.
	root := t.TempDir()
	cfg := DefaultConfig()
	cfg.BackupDir = filepath.Join(root, "backups")
	cfg.MailDataDir = filepath.Join(root, "mail")
	cfg.DKIMDir = filepath.Join(root, "dkim")
	cfg.ConfigDir = filepath.Join(root, "etc-vectis")
	cfg.SnapshotDir = filepath.Join(root, "snapshots")
	cfg.DBHost, cfg.DBPort = dbCfg.Host, dbCfg.Port
	cfg.DBName, cfg.DBUser, cfg.DBPassword = dbCfg.Name, dbCfg.User, dbCfg.Password
	cfg.ComposePath = filepath.Join(root, "nonexistent-compose.yml") // never invoked
	// Exercise the encrypted (.enc) path — this is what production uses.
	cfg.EncryptionKey = "test-encryption-key-round-trip-please"

	for _, d := range []string{cfg.BackupDir, cfg.MailDataDir, cfg.DKIMDir, cfg.ConfigDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	// Sample payloads across all three archived trees.
	mailFile := filepath.Join(cfg.MailDataDir, "example.com", "alice", "cur", "msg1")
	dkimFile := filepath.Join(cfg.DKIMDir, "example.com.private")
	configFile := filepath.Join(cfg.ConfigDir, "config.yaml")
	secretsFile := filepath.Join(cfg.ConfigDir, "secrets.yaml") // must be excluded
	writeFile(t, mailFile, "From: a@example.com\nSubject: hi\n\nbody\n")
	writeFile(t, dkimFile, "FAKE-DKIM-PRIVATE-KEY\n")
	writeFile(t, configFile, "version: dr-test\n")
	writeFile(t, secretsFile, "db_password: must-not-be-archived\n")

	mgr := NewManager(pool, logger, cfg)
	// No compose stack in CI: make service control inert.
	mgr.stopServicesFn = func(context.Context) error { return nil }
	mgr.startServicesFn = func(context.Context) error { return nil }
	mgr.healthCheckFn = func(context.Context) error { return nil }

	// --- Back up ---
	archivePath, size, err := mgr.Create(ctx, nil)
	if err != nil {
		t.Fatalf("create backup: %v", err)
	}
	if size <= 0 {
		t.Fatalf("backup size = %d, want > 0", size)
	}
	if filepath.Ext(archivePath) != ".enc" {
		t.Fatalf("expected encrypted archive (.enc), got %q", archivePath)
	}
	if _, err := os.Stat(archivePath); err != nil {
		t.Fatalf("archive not written: %v", err)
	}

	// --- Simulate disaster: lose the DB row and the on-disk trees ---
	mustExec(ctx, t, pool, `DROP TABLE dr_canary`)
	for _, d := range []string{cfg.MailDataDir, cfg.DKIMDir, cfg.ConfigDir} {
		if err := os.RemoveAll(d); err != nil {
			t.Fatal(err)
		}
	}

	// --- Restore ---
	if err := mgr.Restore(ctx, archivePath, nil); err != nil {
		t.Fatalf("restore: %v", err)
	}

	// --- DB round-tripped ---
	var got string
	if err := pool.QueryRow(ctx, `SELECT token FROM dr_canary`).Scan(&got); err != nil {
		t.Fatalf("canary row not restored: %v", err)
	}
	if got != token {
		t.Fatalf("canary token = %q, want %q", got, token)
	}

	// --- Files round-tripped ---
	assertFileContains(t, mailFile, "Subject: hi")
	assertFileContains(t, dkimFile, "FAKE-DKIM-PRIVATE-KEY")
	assertFileContains(t, configFile, "version: dr-test")

	// --- secrets.yaml was excluded from the backup (security guarantee) ---
	if _, err := os.Stat(secretsFile); !os.IsNotExist(err) {
		t.Fatalf("secrets.yaml must be absent after restore (excluded from backups); stat err = %v", err)
	}
}

// --- helpers ---

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envOrInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func mustExec(ctx context.Context, t *testing.T, pool *pgxpool.Pool, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertFileContains(t *testing.T, path, want string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(b), want) {
		t.Fatalf("%s does not contain %q; got %q", path, want, string(b))
	}
}
