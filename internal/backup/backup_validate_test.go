package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

// buildTarGz writes a gzip'd tar of the given members to path.
func buildTarGz(t *testing.T, path string, members map[string][]byte) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create tgz: %v", err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for name, data := range members {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(data))}); err != nil {
			t.Fatalf("tar header: %v", err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatalf("tar write: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar close: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
}

func testManager(key string) *Manager {
	return NewManager(nil, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{EncryptionKey: key})
}

// TestValidateEncryptedArchiveStreaming proves validateArchive fully verifies an
// encrypted archive by streaming (multi-chunk) — accepting a valid one and
// rejecting a tail-truncated one (the case a first-chunk probe would miss).
func TestValidateEncryptedArchiveStreaming(t *testing.T) {
	dir := t.TempDir()
	inner := filepath.Join(dir, "inner.tar.gz")
	buildTarGz(t, inner, map[string][]byte{
		"database.sql":             []byte("-- pg dump\nCREATE TABLE x();\n"),
		"var/vectis/mail/big.mbox": bytes.Repeat([]byte("mailmailmail\n"), 300000), // spans several MiB -> multi-chunk
	})

	enc := filepath.Join(dir, "backup.tar.gz.enc")
	if err := encryptFile(inner, enc, "k3y"); err != nil {
		t.Fatalf("encryptFile: %v", err)
	}

	m := testManager("k3y")
	if err := m.validateArchive(context.Background(), enc); err != nil {
		t.Fatalf("validate valid encrypted archive: %v", err)
	}

	// Tail-truncate the archive: the streaming AEAD final-flag/EOF check must fail.
	raw, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(enc, raw[:len(raw)-200], 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.validateArchive(context.Background(), enc); err == nil {
		t.Fatal("validateArchive accepted a truncated encrypted archive — must fail closed")
	}
}

// TestRetainDaysValidateCap: retention above MaxRetainDays is rejected so the
// prune cutoff arithmetic can never overflow into the future.
func TestRetainDaysValidateCap(t *testing.T) {
	base := Settings{Schedule: "0 2 * * *", Timezone: "UTC"}
	ok := base
	ok.RetainDays = MaxRetainDays
	if err := ok.Validate(); err != nil {
		t.Fatalf("RetainDays=MaxRetainDays should be valid: %v", err)
	}
	bad := base
	bad.RetainDays = MaxRetainDays + 1
	if err := bad.Validate(); err == nil {
		t.Fatal("RetainDays above MaxRetainDays should be rejected")
	}
}
