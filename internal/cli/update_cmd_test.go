package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// TestInstallBinary_DirectRename verifies the fast path: when the caller owns
// the destination directory, installBinary renames into place without ever
// reaching for sudo. The contents must match the source byte-for-byte.
func TestInstallBinary_DirectRename(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "vectis.new")
	dest := filepath.Join(dir, "vectis")

	want := []byte("fake-binary-payload")
	if err := os.WriteFile(src, want, 0o755); err != nil {
		t.Fatalf("write src: %v", err)
	}

	if err := installBinary(src, dest); err != nil {
		t.Fatalf("installBinary: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("dest contents = %q, want %q", got, want)
	}

	// A rename consumes the source; it must no longer exist.
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Errorf("src still exists after rename (err=%v)", err)
	}
}
