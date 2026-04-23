package orchestrator

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleCompose = `services:
  traefik:
    image: traefik:v3.3
    container_name: vectis-traefik
  api:
    image: ghcr.io/veltara-works/vectis-api:v0.1.0-rc28
    container_name: vectis-api
  orchestrator:
    image: ghcr.io/veltara-works/vectis-orchestrator:v0.1.0-rc28
    container_name: vectis-orchestrator
  postfix:
    image: ghcr.io/veltara-works/vectis-postfix:v0.1.0-rc28
    container_name: vectis-postfix
`

func writeTempCompose(t *testing.T, content string) string {
	t.Helper()
	tmp := t.TempDir()
	p := filepath.Join(tmp, "docker-compose.yml")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func changesRC28toRC29() []PlanChange {
	return []PlanChange{
		{Service: "api", Type: "update",
			OldImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc28",
			NewImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc29"},
		{Service: "orchestrator", Type: "update",
			OldImage: "ghcr.io/veltara-works/vectis-orchestrator:v0.1.0-rc28",
			NewImage: "ghcr.io/veltara-works/vectis-orchestrator:v0.1.0-rc29"},
		{Service: "postfix", Type: "update",
			OldImage: "ghcr.io/veltara-works/vectis-postfix:v0.1.0-rc28",
			NewImage: "ghcr.io/veltara-works/vectis-postfix:v0.1.0-rc29"},
	}
}

func TestRewriteComposeTags_HappyPath(t *testing.T) {
	composePath := writeTempCompose(t, sampleCompose)
	backupPath := composePath + ".bak"

	rewritten, err := RewriteComposeTags(composePath, changesRC28toRC29(), backupPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rewritten {
		t.Fatalf("expected rewritten=true (3 tag changes)")
	}

	// All three new images should be in the rewritten file.
	data, _ := os.ReadFile(composePath)
	out := string(data)
	for _, want := range []string{
		"ghcr.io/veltara-works/vectis-api:v0.1.0-rc29",
		"ghcr.io/veltara-works/vectis-orchestrator:v0.1.0-rc29",
		"ghcr.io/veltara-works/vectis-postfix:v0.1.0-rc29",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rewritten compose missing %q", want)
		}
	}
	// The old rc28 tags should all be gone.
	if strings.Contains(out, "v0.1.0-rc28") {
		t.Errorf("rewritten compose still contains v0.1.0-rc28: %s", out)
	}

	// Backup should contain the ORIGINAL pre-rewrite content.
	backup, err := os.ReadFile(backupPath)
	if err != nil {
		t.Fatalf("read backup: %v", err)
	}
	if string(backup) != sampleCompose {
		t.Errorf("backup content differs from original;\nwant:\n%s\n\ngot:\n%s", sampleCompose, string(backup))
	}

	// Unchanged services (traefik) should still have their original image.
	if !strings.Contains(out, "traefik:v3.3") {
		t.Errorf("non-target service lost its image: %s", out)
	}
}

func TestRewriteComposeTags_NoopWhenTagsMatch(t *testing.T) {
	// Compose file already at rc29; plan still says "rc29 → rc29" (shouldn't
	// happen in practice but defensive) OR plan has same-tag entries.
	composePath := writeTempCompose(t, sampleCompose)
	backupPath := composePath + ".bak"

	changes := []PlanChange{
		{Service: "api", Type: "update",
			OldImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc28",
			NewImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc28"}, // same
	}
	rewritten, err := RewriteComposeTags(composePath, changes, backupPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rewritten {
		t.Fatalf("expected rewritten=false when OldImage == NewImage")
	}
	// Backup should have been cleaned up.
	if _, err := os.Stat(backupPath); !os.IsNotExist(err) {
		t.Errorf("backup should be removed when no rewrite happened; stat err = %v", err)
	}
}

func TestRewriteComposeTags_SkipsUnmatchedOldImage(t *testing.T) {
	// Change references an OldImage that isn't in the file (e.g., service
	// not in compose). Should silently skip that change, not error.
	composePath := writeTempCompose(t, sampleCompose)
	backupPath := composePath + ".bak"

	changes := []PlanChange{
		{Service: "api", Type: "update",
			OldImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc28",
			NewImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc29"},
		{Service: "ghost", Type: "update",
			OldImage: "ghcr.io/veltara-works/vectis-ghost:v0.1.0-rc28",
			NewImage: "ghcr.io/veltara-works/vectis-ghost:v0.1.0-rc29"}, // not in file
	}
	rewritten, err := RewriteComposeTags(composePath, changes, backupPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rewritten {
		t.Fatalf("expected rewritten=true — api change should have applied")
	}
	data, _ := os.ReadFile(composePath)
	if !strings.Contains(string(data), "vectis-api:v0.1.0-rc29") {
		t.Errorf("api rewrite should have landed even though ghost didn't match")
	}
}

func TestRewriteComposeTags_OnlyRewritesImageLines(t *testing.T) {
	// Put the old image inside a comment AND an image line. Only the image
	// line should be touched.
	compose := `services:
  # note: we used to run ghcr.io/veltara-works/vectis-api:v0.1.0-rc28 on this box
  api:
    image: ghcr.io/veltara-works/vectis-api:v0.1.0-rc28
    container_name: vectis-api
`
	composePath := writeTempCompose(t, compose)
	backupPath := composePath + ".bak"

	changes := []PlanChange{{
		Service: "api", Type: "update",
		OldImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc28",
		NewImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc29",
	}}
	rewritten, err := RewriteComposeTags(composePath, changes, backupPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rewritten {
		t.Fatalf("expected rewritten=true")
	}
	data, _ := os.ReadFile(composePath)
	out := string(data)

	// Comment preserved verbatim (still references rc28).
	if !strings.Contains(out, "# note: we used to run ghcr.io/veltara-works/vectis-api:v0.1.0-rc28") {
		t.Errorf("comment should be preserved; got:\n%s", out)
	}
	// Image line updated.
	if !strings.Contains(out, "image: ghcr.io/veltara-works/vectis-api:v0.1.0-rc29") {
		t.Errorf("image line should be rewritten; got:\n%s", out)
	}
}

func TestRewriteComposeTags_PreservesLeadingWhitespace(t *testing.T) {
	// Deeply-indented image lines (e.g. nested under extensions) should keep
	// their indentation after rewrite.
	compose := "services:\n  api:\n    image:   ghcr.io/veltara-works/vectis-api:v0.1.0-rc28   \n"
	composePath := writeTempCompose(t, compose)
	backupPath := composePath + ".bak"

	changes := []PlanChange{{
		Service: "api", Type: "update",
		OldImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc28",
		NewImage: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc29",
	}}
	rewritten, err := RewriteComposeTags(composePath, changes, backupPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !rewritten {
		t.Fatalf("expected rewritten=true")
	}
	data, _ := os.ReadFile(composePath)
	// Must still have the 4-space indent before `image:`.
	if !strings.Contains(string(data), "    image:   ghcr.io/veltara-works/vectis-api:v0.1.0-rc29") {
		t.Errorf("indentation/whitespace lost:\n%s", string(data))
	}
}

func TestRewriteComposeTags_ErrorsOnMissingCompose(t *testing.T) {
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "does-not-exist.yml")
	_, err := RewriteComposeTags(missing, changesRC28toRC29(), filepath.Join(tmp, "bak.yml"))
	if err == nil {
		t.Fatal("expected error when compose path doesn't exist")
	}
}

func TestRestoreComposeBackup_RoundTripsContent(t *testing.T) {
	composePath := writeTempCompose(t, sampleCompose)
	backupPath := composePath + ".bak"

	// First, do a rewrite so the file changes and the backup captures the original.
	if _, err := RewriteComposeTags(composePath, changesRC28toRC29(), backupPath); err != nil {
		t.Fatal(err)
	}
	// Sanity: compose now has rc29.
	data, _ := os.ReadFile(composePath)
	if !strings.Contains(string(data), "v0.1.0-rc29") {
		t.Fatal("precondition failed: compose should be rc29 after rewrite")
	}

	// Restore from backup.
	if err := RestoreComposeBackup(composePath, backupPath); err != nil {
		t.Fatalf("restore failed: %v", err)
	}
	restored, _ := os.ReadFile(composePath)
	if string(restored) != sampleCompose {
		t.Errorf("restored content differs from original;\nwant:\n%s\n\ngot:\n%s", sampleCompose, string(restored))
	}
}

func TestRestoreComposeBackup_NoopOnMissingBackup(t *testing.T) {
	composePath := writeTempCompose(t, sampleCompose)
	// Deliberately DON'T write a backup first.
	before, _ := os.ReadFile(composePath)
	if err := RestoreComposeBackup(composePath, composePath+".bak"); err != nil {
		t.Fatalf("restore should no-op, not error, when backup absent: %v", err)
	}
	after, _ := os.ReadFile(composePath)
	if string(before) != string(after) {
		t.Errorf("file should be unchanged when backup was missing")
	}
}

func TestComposeBackupPathFor_DerivedFromSnapshotPath(t *testing.T) {
	cases := []struct{ in, want string }{
		{"/var/vectis/snapshots/pre-update-2026-04-23T10-00.sql", "/var/vectis/snapshots/pre-update-2026-04-23T10-00-compose.yml"},
		{"/tmp/a.sql", "/tmp/a-compose.yml"},
		{"/no-extension", "/no-extension-compose.yml"},
	}
	for _, tc := range cases {
		got := composeBackupPathFor(tc.in)
		if got != tc.want {
			t.Errorf("composeBackupPathFor(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
