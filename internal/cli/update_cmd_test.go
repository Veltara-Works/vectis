package cli

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVerifyManifestBinaryDigest is the REL-1 regression net: the self-update
// path must bind the downloaded binary to the sha256 named by the SIGNED release
// manifest, so an origin compromise cannot serve an older still-signed binary
// behind the current tag. An absent digest is a benign skip (pre-REL-1 manifest);
// a mismatch or malformed digest is attack-class (errReleaseVerification).
func TestVerifyManifestBinaryDigest(t *testing.T) {
	const good = "8bd19c3a278a2cb0602b362d9fd69566c332e053a6c805119ba0cf684601db90"

	// Absent field → benign skip (fall back to the Ed25519 binary signature).
	if err := verifyManifestBinaryDigest("", good); err != nil {
		t.Errorf("empty manifest digest: want nil (skip), got %v", err)
	}
	// Present + matching → pass.
	if err := verifyManifestBinaryDigest(good, good); err != nil {
		t.Errorf("matching digest: want nil, got %v", err)
	}
	// Present + mismatching → attack-class refusal (downgrade defence).
	mismatch := verifyManifestBinaryDigest(good, strings.Repeat("b", 64))
	if mismatch == nil {
		t.Error("mismatching digest: want error, got nil")
	} else if !errors.Is(mismatch, errReleaseVerification) {
		t.Errorf("mismatching digest: want errReleaseVerification, got %v", mismatch)
	}
	// Present but malformed → attack-class refusal (must not be trusted).
	for _, bad := range []string{"sha256:" + good, strings.Repeat("a", 63), strings.ToUpper(good), "not-a-digest"} {
		err := verifyManifestBinaryDigest(bad, good)
		if err == nil {
			t.Errorf("malformed manifest digest %q: want error, got nil", bad)
		} else if !errors.Is(err, errReleaseVerification) {
			t.Errorf("malformed manifest digest %q: want errReleaseVerification, got %v", bad, err)
		}
	}
}

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
	bigDest := filepath.Join(dir, "big.new")
	if err := downloadFile(srvBig.Client(), srvBig.URL, bigDest); err == nil {
		t.Fatal("downloadFile accepted an oversize body; REL-4 regression")
	}
	// The partial download must not be left behind.
	if _, err := os.Stat(bigDest); !os.IsNotExist(err) {
		t.Fatalf("oversize download left a partial file at %s (stat err=%v)", bigDest, err)
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
