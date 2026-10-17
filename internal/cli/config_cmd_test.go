package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Veltara-Works/vectis/internal/engine"
)

func TestSplitCompose(t *testing.T) {
	files := []engine.GeneratedFile{
		{RelPath: "postfix/main.cf", Content: []byte("a")},
		{RelPath: "docker-compose.yml", Content: []byte("services:")},
		{RelPath: "rspamd/dkim_signing.conf", Content: []byte("b")},
	}
	compose, rest := splitCompose(files)
	if len(compose) != 1 || compose[0].RelPath != "docker-compose.yml" {
		t.Fatalf("expected exactly the compose file, got %+v", compose)
	}
	if len(rest) != 2 {
		t.Fatalf("expected 2 non-compose files, got %d", len(rest))
	}
	for _, f := range rest {
		if f.RelPath == "docker-compose.yml" {
			t.Errorf("compose leaked into rest: %s", f.RelPath)
		}
	}
}

// TestWriteAllFiles_ComposeGoesToConfigDir locks in the two-compose-path fix:
// the docker-compose.yml must land in configDir (the LIVE compose the running
// stack reads), while per-service configs go to genDir.
func TestWriteAllFiles_ComposeGoesToConfigDir(t *testing.T) {
	genDir := t.TempDir()
	configDir := t.TempDir()
	files := []engine.GeneratedFile{
		{RelPath: "docker-compose.yml", Content: []byte("services: {}\n")},
		{RelPath: "postfix/main.cf", Content: []byte("# main.cf\n")},
	}

	if err := writeAllFiles(genDir, configDir, files); err != nil {
		t.Fatalf("writeAllFiles: %v", err)
	}

	// Compose in configDir (the canonical/live location) — the actual fix.
	if _, err := os.Stat(filepath.Join(configDir, "docker-compose.yml")); err != nil {
		t.Errorf("docker-compose.yml not written to configDir: %v", err)
	}
	// Compose also in genDir (back-compat copy).
	if _, err := os.Stat(filepath.Join(genDir, "docker-compose.yml")); err != nil {
		t.Errorf("docker-compose.yml not written to genDir: %v", err)
	}
	// Per-service config only in genDir.
	if _, err := os.Stat(filepath.Join(genDir, "postfix/main.cf")); err != nil {
		t.Errorf("postfix/main.cf not written to genDir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "postfix/main.cf")); !os.IsNotExist(err) {
		t.Errorf("postfix/main.cf should NOT be written to configDir")
	}
}

// TestComposeChanged: apply warns that compose-level settings need a container
// recreate only when the docker-compose.yml itself changed (#261 review).
func TestComposeChanged(t *testing.T) {
	if composeChanged([]engine.FileDiff{{RelPath: "rspamd/actions.conf", Status: "modified"}}) {
		t.Error("a per-service config diff alone must not report a compose change")
	}
	if !composeChanged([]engine.FileDiff{
		{RelPath: "rspamd/actions.conf", Status: "modified"},
		{RelPath: composeRelPath, Status: "modified"},
	}) {
		t.Error("a docker-compose.yml diff must report a compose change")
	}
	if composeChanged(nil) {
		t.Error("no diffs must not report a compose change")
	}
}

func TestCarryLiveImagePins(t *testing.T) {
	const pin = "@sha256:d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4"
	dir := t.TempDir()
	files := func() []engine.GeneratedFile {
		return []engine.GeneratedFile{
			{RelPath: composeRelPath, Content: []byte("services:\n  api:\n    image: ghcr.io/veltara-works/vectis-api:v0.1.56\n  webmail:\n    image: ghcr.io/veltara-works/vectis-webmail:v0.1.57\n")},
			{RelPath: "postfix/main.cf", Content: []byte("myhostname = x\n")},
		}
	}

	// Fresh install: no live compose, nothing to carry, no error.
	if unc, err := carryLiveImagePins(dir, files()); err != nil || len(unc) != 0 {
		t.Fatalf("no live compose: uncarried=%v err=%v", unc, err)
	}

	// Live: api + webmail pinned at v0.1.56, plus clamav, which the new render dropped.
	live := "services:\n  api:\n    image: ghcr.io/veltara-works/vectis-api:v0.1.56" + pin +
		"\n  webmail:\n    image: ghcr.io/veltara-works/vectis-webmail:v0.1.56" + pin +
		"\n  clamav:\n    image: ghcr.io/veltara-works/vectis-clamav:v0.1.56" + pin + "\n"
	if err := os.WriteFile(filepath.Join(dir, composeRelPath), []byte(live), 0o600); err != nil {
		t.Fatal(err)
	}
	fs1 := files()
	unc, err := carryLiveImagePins(dir, fs1)
	if err != nil {
		t.Fatal(err)
	}
	// Only webmail (tag differs) is reported; the removed clamav is not.
	if len(unc) != 1 || unc[0] != "webmail" {
		t.Fatalf("uncarried = %v, want [webmail]", unc)
	}
	if got := string(fs1[0].Content); !strings.Contains(got, "vectis-api:v0.1.56"+pin+"\n") || strings.Contains(got, "vectis-webmail:v0.1.57@") {
		t.Errorf("compose after carry:\n%s", got)
	}
	if string(fs1[1].Content) != "myhostname = x\n" {
		t.Error("non-compose files must be untouched")
	}
}
