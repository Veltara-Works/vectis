package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

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
