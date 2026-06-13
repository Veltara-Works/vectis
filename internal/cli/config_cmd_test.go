package cli

import (
	"os"
	"path/filepath"
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
