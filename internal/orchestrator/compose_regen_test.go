package orchestrator

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Veltara-Works/vectis/internal/config"
	"github.com/Veltara-Works/vectis/internal/engine"
)

const sampleOldCompose = `services:
  api:
    image: ghcr.io/veltara-works/vectis-api:v0.1.0-rc28
    container_name: vectis-api
`

const sampleNewCompose = `services:
  api:
    image: ghcr.io/veltara-works/vectis-api:v0.1.0-rc29
    container_name: vectis-api
    volumes:
      - /var/vectis/generated:/var/vectis/generated:ro
`

func TestRegenerateCompose_RewritesWhenContentChanges(t *testing.T) {
	composePath := writeTempCompose(t, sampleOldCompose)
	backupPath := composePath + ".bak"

	gen := func(_ context.Context, releaseTag string) ([]byte, error) {
		if releaseTag != "v0.1.0-rc29" {
			t.Errorf("expected releaseTag=v0.1.0-rc29, got %q", releaseTag)
		}
		return []byte(sampleNewCompose), nil
	}

	rewritten, err := RegenerateCompose(context.Background(), composePath, backupPath, "v0.1.0-rc29", gen)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rewritten {
		t.Fatalf("expected rewritten=true (content differs)")
	}

	// On-disk compose now matches generator output (incl. new bind mount line).
	got, _ := os.ReadFile(composePath)
	if string(got) != sampleNewCompose {
		t.Errorf("compose content does not match generator output:\nwant:\n%s\n\ngot:\n%s", sampleNewCompose, got)
	}
	if !strings.Contains(string(got), "/var/vectis/generated:/var/vectis/generated:ro") {
		t.Errorf("regenerated compose missing new bind mount — proves §10 picks up structural template changes, not just tags")
	}

	// Backup must hold pre-rewrite content for rollback.
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != sampleOldCompose {
		t.Errorf("backup content differs from original;\nwant:\n%s\n\ngot:\n%s", sampleOldCompose, string(backup))
	}
}

func TestRegenerateCompose_NoOpWhenIdentical(t *testing.T) {
	composePath := writeTempCompose(t, sampleOldCompose)
	backupPath := composePath + ".bak"

	gen := func(_ context.Context, _ string) ([]byte, error) {
		return []byte(sampleOldCompose), nil
	}

	rewritten, err := RegenerateCompose(context.Background(), composePath, backupPath, "v0.1.0-rc29", gen)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rewritten {
		t.Fatalf("expected rewritten=false when generated content matches on-disk byte-for-byte")
	}
	// Backup must be cleaned up so rollback doesn't pointlessly restore an identical file.
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Errorf("expected backup to be removed on no-op; stat err = %v", err)
	}
	// Compose unchanged.
	got, _ := os.ReadFile(composePath)
	if string(got) != sampleOldCompose {
		t.Errorf("compose should be unchanged on no-op")
	}
}

func TestRegenerateCompose_BackupContainsPreRewriteBytes(t *testing.T) {
	// Even if the generator returns a newer file, the backup snapshot must
	// hold the bytes that were on disk PRE-rewrite — so rollback restores
	// the install-time compose, not the about-to-be-written one.
	composePath := writeTempCompose(t, sampleOldCompose)
	backupPath := composePath + ".bak"

	gen := func(_ context.Context, _ string) ([]byte, error) {
		return []byte(sampleNewCompose), nil
	}
	if _, err := RegenerateCompose(context.Background(), composePath, backupPath, "v0.1.0-rc29", gen); err != nil {
		t.Fatalf("regenerate: %v", err)
	}

	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != sampleOldCompose {
		t.Errorf("backup should hold pre-rewrite bytes for rollback;\nwant:\n%s\n\ngot:\n%s", sampleOldCompose, string(backup))
	}

	// Confirm RestoreComposeBackup actually round-trips through this backup.
	if err := RestoreComposeBackup(composePath, backupPath); err != nil {
		t.Fatalf("restore backup: %v", err)
	}
	got, _ := os.ReadFile(composePath)
	if string(got) != sampleOldCompose {
		t.Errorf("rollback restore produced wrong content;\nwant:\n%s\n\ngot:\n%s", sampleOldCompose, got)
	}
}

func TestRegenerateCompose_NilGeneratorErrors(t *testing.T) {
	composePath := writeTempCompose(t, sampleOldCompose)
	backupPath := composePath + ".bak"

	_, err := RegenerateCompose(context.Background(), composePath, backupPath, "v0.1.0-rc29", nil)
	if err == nil {
		t.Fatal("expected error when generator is nil")
	}
}

func TestRegenerateCompose_GeneratorErrorRemovesBackup(t *testing.T) {
	// If the generator fails, we must NOT leave a stale backup behind —
	// rollback would otherwise pointlessly restore the same file we never
	// rewrote, and worse, leave operators thinking an Apply happened.
	composePath := writeTempCompose(t, sampleOldCompose)
	backupPath := composePath + ".bak"

	gen := func(_ context.Context, _ string) ([]byte, error) {
		return nil, errors.New("simulated DB outage")
	}
	rewritten, err := RegenerateCompose(context.Background(), composePath, backupPath, "v0.1.0-rc29", gen)
	if err == nil {
		t.Fatal("expected error from failing generator")
	}
	if rewritten {
		t.Fatal("expected rewritten=false on generator error")
	}
	if _, statErr := os.Stat(backupPath); !os.IsNotExist(statErr) {
		t.Errorf("expected backup removed on generator error; stat err = %v", statErr)
	}
	// On-disk compose must be untouched.
	got, _ := os.ReadFile(composePath)
	if string(got) != sampleOldCompose {
		t.Errorf("compose should be untouched when generator errors")
	}
}

func TestRegenerateCompose_EmptyGeneratedContentErrors(t *testing.T) {
	composePath := writeTempCompose(t, sampleOldCompose)
	backupPath := composePath + ".bak"

	gen := func(_ context.Context, _ string) ([]byte, error) {
		return []byte{}, nil
	}
	_, err := RegenerateCompose(context.Background(), composePath, backupPath, "v0.1.0-rc29", gen)
	if err == nil {
		t.Fatal("expected error when generator returns empty bytes (would otherwise blank the compose file)")
	}
	got, _ := os.ReadFile(composePath)
	if string(got) != sampleOldCompose {
		t.Errorf("compose must remain intact on empty-gen error")
	}
}

func TestRegenerateCompose_MissingComposeFileErrors(t *testing.T) {
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "does-not-exist.yml")
	gen := func(_ context.Context, _ string) ([]byte, error) {
		return []byte(sampleNewCompose), nil
	}
	_, err := RegenerateCompose(context.Background(), missing, filepath.Join(tmp, "bak.yml"), "v0.1.0-rc29", gen)
	if err == nil {
		t.Fatal("expected error when compose path doesn't exist")
	}
}

// TestRegenerateCompose_PostApplyMatchesTemplate is the §10 integration
// regression: simulate a real Apply by writing an old compose, regenerate
// against the engine's embedded templates, and assert the result matches
// the template-rendered compose byte-for-byte. Locks in the contract that
// after Apply the on-disk compose is identical to engine.Generate output
// — no drift, no manual host-side patches required for v0.1.2's new spam
// mounts (or any future structural template change) to land on upgrade.
func TestRegenerateCompose_PostApplyMatchesTemplate(t *testing.T) {
	composePath := writeTempCompose(t, sampleOldCompose)
	backupPath := composePath + ".bak"

	// Build the same generator wiring main.go uses, minus the DB-backed
	// domain list (passed in directly here).
	gen := func(_ context.Context, releaseTag string) ([]byte, error) {
		data := buildTemplateData()
		if releaseTag != "" {
			data.Version = releaseTag
		}
		files, err := engine.Generate(data)
		if err != nil {
			return nil, err
		}
		for _, f := range files {
			if f.RelPath == "docker-compose.yml" {
				return f.Content, nil
			}
		}
		t.Fatal("docker-compose.yml not present in rendered templates")
		return nil, nil
	}

	rewritten, err := RegenerateCompose(context.Background(), composePath, backupPath, "v0.1.3", gen)
	if err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if !rewritten {
		t.Fatal("expected rewritten=true (sample old compose differs from template)")
	}

	// Idempotence: a second regen against the now-on-disk content must be a no-op.
	rewritten2, err := RegenerateCompose(context.Background(), composePath, backupPath, "v0.1.3", gen)
	if err != nil {
		t.Fatalf("second regenerate: %v", err)
	}
	if rewritten2 {
		t.Fatal("expected rewritten=false on second regen (post-Apply state must be idempotent vs template)")
	}

	// Surface the template-driven content has the v0.1.2 spam wiring landed
	// after Apply — proves §10 brings new mounts in even when starting from
	// an old install-time compose.
	got, _ := os.ReadFile(composePath)
	if !strings.Contains(string(got), "/var/vectis/generated/rspamd:/var/vectis/generated/rspamd") {
		t.Errorf("regenerated compose missing /var/vectis/generated/rspamd bind mount:\n%s", got)
	}
	if !strings.Contains(string(got), "ghcr.io/veltara-works/vectis-api:v0.1.3") {
		t.Errorf("regenerated compose missing v0.1.3 api tag (release tag override didn't take):\n%s", got)
	}
}

// buildTemplateData mirrors the engine_test.go testData() helper closely
// enough to exercise the full compose rendering path without pulling in
// engine_test internals.
func buildTemplateData() *engine.TemplateData {
	return &engine.TemplateData{
		Hostname: "mail.example.com",
		TLS:      config.TLSConfig{Provider: "letsencrypt", Email: "admin@example.com"},
		ClamAV:   engine.ClamAVKnobs{Profile: "none"},
		Rspamd: config.RspamdConfig{
			SpamThreshold:   15.0,
			RejectThreshold: 999,
			GreylistEnabled: false,
		},
		Postfix: config.PostfixConfig{
			MessageSizeLimit: 52428800,
			SmtpBanner:       "$myhostname ESMTP",
		},
		Dovecot: config.DovecotConfig{
			MailLocation:   "maildir:/var/vectis/mail/%d/%n/Maildir",
			QuotaDefaultMB: 1024,
		},
		Logging: config.LoggingConfig{
			Level: "info", Driver: "json-file", MaxSizeMB: 50, MaxFiles: 5,
		},
		Admin: config.AdminConfig{ListenAddr: ":8080", SessionTTLHours: 24},
		Database: config.DatabaseSecrets{
			Host: "postgres", Port: 5432, Name: "vectis",
			SuperuserPassword: "secret_super",
			APIUser:           "vectis_api", APIPassword: "secret_api",
			PostfixUser: "vectis_postfix", PostfixPassword: "secret_postfix",
			DovecotUser: "vectis_dovecot", DovecotPassword: "secret_dovecot",
		},
		Valkey: config.ValkeySecrets{Host: "valkey", Port: 6379, Password: "secret_valkey"},
	}
}
