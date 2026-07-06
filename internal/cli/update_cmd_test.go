package cli

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestDownloadFile_Bounded is the REL-4 regression net: downloadFile must cap
// the response body so a hostile origin cannot exhaust host disk. A body within
// the cap is written verbatim; a body exceeding maxBinaryDownload is refused
// (not silently truncated). Uses a tiny handler and asserts the size gate via
// the +1 boundary logic, without materialising 512 MiB.
func TestDownloadFile_Bounded(t *testing.T) {
	// Normal path: small body downloads and matches byte-for-byte.
	payload := []byte("genuine-binary-bytes")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "vectis.new")
	if err := downloadFile(srv.Client(), srv.URL, dest); err != nil {
		t.Fatalf("downloadFile (normal): %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil || string(got) != string(payload) {
		t.Fatalf("downloaded = %q err=%v, want %q", got, err, payload)
	}

	// Oversize path: a body larger than the cap is rejected, not truncated.
	// Lower the cap for the test so we exercise the boundary without moving
	// 512 MiB.
	orig := maxBinaryDownload
	maxBinaryDownload = 64
	defer func() { maxBinaryDownload = orig }()
	srvBig := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, maxBinaryDownload+16))
	}))
	defer srvBig.Close()
	if err := downloadFile(srvBig.Client(), srvBig.URL, filepath.Join(dir, "big.new")); err == nil {
		t.Fatal("downloadFile accepted an oversize body; REL-4 regression")
	}
}

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
