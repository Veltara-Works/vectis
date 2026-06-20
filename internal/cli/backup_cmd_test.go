package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Veltara-Works/vectis/internal/backup"
)

// TestRestoreDBConfig locks down how `vectis backup restore --db-host` retargets
// the restore Config. The two paths differ deliberately: the default uses
// docker exec as the superuser, while --db-host switches to a TCP restore that
// MUST connect as the superuser (not the app user) so the dump can recreate
// superuser-owned objects like the pgcrypto extension (DR drill Finding B).
func TestRestoreDBConfig(t *testing.T) {
	t.Run("no db-host keeps docker-exec superuser path", func(t *testing.T) {
		cfg := restoreDBConfig(backup.DefaultConfig(), "", 5432, "superpass")
		if cfg.DirectDB {
			t.Fatalf("DirectDB should be false without --db-host")
		}
		if cfg.SuperuserPassword != "superpass" {
			t.Fatalf("SuperuserPassword = %q, want superpass", cfg.SuperuserPassword)
		}
		if cfg.DBHost != "postgres" {
			t.Fatalf("DBHost = %q, want default postgres", cfg.DBHost)
		}
	})

	t.Run("db-host opts into TCP restore as superuser", func(t *testing.T) {
		cfg := restoreDBConfig(backup.DefaultConfig(), "10.0.0.5", 6543, "superpass")
		if !cfg.DirectDB {
			t.Fatalf("DirectDB should be true with --db-host")
		}
		if cfg.DBHost != "10.0.0.5" {
			t.Fatalf("DBHost = %q, want 10.0.0.5", cfg.DBHost)
		}
		if cfg.DBPort != 6543 {
			t.Fatalf("DBPort = %d, want 6543", cfg.DBPort)
		}
		// Must connect as the superuser, not the app user.
		if cfg.DBUser != cfg.DBSuperuser {
			t.Fatalf("DBUser = %q, want superuser %q", cfg.DBUser, cfg.DBSuperuser)
		}
		if cfg.DBPassword != "superpass" {
			t.Fatalf("DBPassword = %q, want superpass", cfg.DBPassword)
		}
	})

	t.Run("zero port leaves Config default", func(t *testing.T) {
		cfg := restoreDBConfig(backup.DefaultConfig(), "10.0.0.5", 0, "superpass")
		if cfg.DBPort != backup.DefaultConfig().DBPort {
			t.Fatalf("DBPort = %d, want default %d", cfg.DBPort, backup.DefaultConfig().DBPort)
		}
	})
}

// TestContainerBackupArgs locks down the docker exec argv used to trigger a
// full backup inside the api container. The flags are load-bearing:
//   - --db-host postgres forces the TCP dump path (the in-container CLI has no
//     docker socket to exec into Postgres);
//   - --json --quiet keep stdout to pure JSON so delegateContainerBackup can
//     parse it (without --quiet the "Creating backup..." line corrupts stdout).
func TestContainerBackupArgs(t *testing.T) {
	args := containerBackupArgs()
	got := strings.Join(args, " ")
	want := "exec vectis-api vectis backup create --db-host postgres --json --quiet"
	if got != want {
		t.Fatalf("containerBackupArgs() = %q, want %q", got, want)
	}
}

// TestDockerCopyArgs locks down the `docker cp` argv used to retrieve a backup
// from inside the api container on installs that don't bind-mount the backups
// dir — the fix for reporting a success path the operator can't reach.
func TestDockerCopyArgs(t *testing.T) {
	got := strings.Join(dockerCopyArgs("/var/vectis/backups/b.tar.gz.enc", "/var/vectis/backups/b.tar.gz.enc"), " ")
	want := "cp vectis-api:/var/vectis/backups/b.tar.gz.enc /var/vectis/backups/b.tar.gz.enc"
	if got != want {
		t.Fatalf("dockerCopyArgs() = %q, want %q", got, want)
	}
}

// TestContainerBackupResultParsing confirms the JSON shape we expect from the
// in-container `vectis backup create --json` round-trips into the result struct
// the host side consumes — including mail_included, which is the whole point of
// delegating (a host-run backup can't capture mail).
func TestContainerBackupResultParsing(t *testing.T) {
	const out = `{
  "path": "/var/vectis/backups/vectis-backup-20260616-080000.tar.gz.enc",
  "size": 5398234,
  "mail_included": true
}`
	var res containerBackupResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if res.Path == "" {
		t.Error("path not parsed")
	}
	if res.Size != 5398234 {
		t.Errorf("size = %d, want 5398234", res.Size)
	}
	if !res.MailIncluded {
		t.Error("mail_included = false, want true")
	}
}
