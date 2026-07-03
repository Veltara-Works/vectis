package backup

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

// writeLegacyEncrypted reproduces the pre-#177 on-disk format — nonce ||
// ciphertext, keyed by a bare SHA-256 of the passphrase — so the test can prove
// decryptFile still restores archives written before the KDF change.
func writeLegacyEncrypted(t *testing.T, path, passphrase string, plaintext []byte) {
	t.Helper()
	keyArr := sha256.Sum256([]byte(passphrase))
	block, err := aes.NewCipher(keyArr[:])
	if err != nil {
		t.Fatalf("legacy cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("legacy gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("legacy nonce: %v", err)
	}
	out := gcm.Seal(nonce, nonce, plaintext, nil)
	if err := os.WriteFile(path, out, 0600); err != nil {
		t.Fatalf("write legacy file: %v", err)
	}
}

// TestEncryptDecryptRoundTrip covers the streaming VXB2 format end to end, and
// asserts the archive carries the VXB2 magic + a per-archive salt (two
// encryptions of the same input never produce identical ciphertext).
func TestEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	const pass = "correct horse battery staple"
	plain := []byte("vectis backup payload \x00\x01\x02 with binary")

	src := filepath.Join(dir, "plain.tar")
	if err := os.WriteFile(src, plain, 0600); err != nil {
		t.Fatalf("write src: %v", err)
	}

	enc := filepath.Join(dir, "archive.enc")
	if err := encryptFile(src, enc, pass); err != nil {
		t.Fatalf("encryptFile: %v", err)
	}

	raw, err := os.ReadFile(enc)
	if err != nil {
		t.Fatalf("read enc: %v", err)
	}
	if string(raw[:len(streamMagicV2)]) != streamMagicV2 {
		t.Errorf("archive missing %q magic; got % x", streamMagicV2, raw[:len(streamMagicV2)])
	}
	if bytes.Contains(raw, plain) {
		t.Error("plaintext leaked into ciphertext")
	}

	// Salt randomness: a second encryption must differ byte-for-byte.
	enc2 := filepath.Join(dir, "archive2.enc")
	if err := encryptFile(src, enc2, pass); err != nil {
		t.Fatalf("encryptFile 2: %v", err)
	}
	raw2, _ := os.ReadFile(enc2)
	if bytes.Equal(raw, raw2) {
		t.Error("two encryptions of the same input are identical — salt/nonce not random")
	}

	out := filepath.Join(dir, "restored.tar")
	if err := decryptFile(enc, out, pass); err != nil {
		t.Fatalf("decryptFile: %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, plain) {
		t.Errorf("round-trip mismatch:\n got %q\nwant %q", got, plain)
	}
}

// TestDecryptLegacyArchive is the backward-compatibility guard for #177: an
// archive written in the old unsalted-SHA256 format must still restore, so the
// KDF change doesn't strand existing production backups.
func TestDecryptLegacyArchive(t *testing.T) {
	dir := t.TempDir()
	const pass = "legacy-passphrase"
	plain := []byte("a backup taken before the KDF change")

	legacy := filepath.Join(dir, "legacy.enc")
	writeLegacyEncrypted(t, legacy, pass, plain)

	out := filepath.Join(dir, "restored.tar")
	if err := decryptFile(legacy, out, pass); err != nil {
		t.Fatalf("decryptFile(legacy): %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, plain) {
		t.Errorf("legacy restore mismatch:\n got %q\nwant %q", got, plain)
	}
}

// writeVXB1Encrypted reproduces the whole-file VXB1 format (magic || salt ||
// nonce || ciphertext, Argon2id key) that shipped before the VXB2 streaming
// change, so the test proves decryptFile's dispatch still restores VXB1 archives
// already sitting on production hosts.
func writeVXB1Encrypted(t *testing.T, path, passphrase string, plaintext []byte) {
	t.Helper()
	salt := make([]byte, backupSaltLen)
	if _, err := rand.Read(salt); err != nil {
		t.Fatalf("vxb1 salt: %v", err)
	}
	block, err := aes.NewCipher(deriveKeyArgon2(passphrase, salt))
	if err != nil {
		t.Fatalf("vxb1 cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("vxb1 gcm: %v", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("vxb1 nonce: %v", err)
	}
	header := append([]byte(backupMagicV1), salt...)
	header = append(header, nonce...)
	out := gcm.Seal(header, nonce, plaintext, nil)
	if err := os.WriteFile(path, out, 0600); err != nil {
		t.Fatalf("write vxb1 file: %v", err)
	}
}

// TestDecryptVXB1Archive is the backward-compatibility guard for the VXB2 change:
// a whole-file VXB1 archive must still restore via decryptFile's magic dispatch.
func TestDecryptVXB1Archive(t *testing.T) {
	dir := t.TempDir()
	const pass = "vxb1-passphrase"
	plain := []byte("a backup written in the whole-file VXB1 format")

	arch := filepath.Join(dir, "vxb1.enc")
	writeVXB1Encrypted(t, arch, pass, plain)

	out := filepath.Join(dir, "restored.tar")
	if err := decryptFile(arch, out, pass); err != nil {
		t.Fatalf("decryptFile(VXB1): %v", err)
	}
	got, _ := os.ReadFile(out)
	if !bytes.Equal(got, plain) {
		t.Errorf("VXB1 restore mismatch:\n got %q\nwant %q", got, plain)
	}
}

// TestDecryptWrongPassphrase and tamper rejection: GCM authentication must fail
// closed on a bad key or a flipped byte rather than emitting garbage plaintext.
func TestDecryptWrongPassphrase(t *testing.T) {
	dir := t.TempDir()
	plain := []byte("sensitive")
	src := filepath.Join(dir, "p.tar")
	if err := os.WriteFile(src, plain, 0600); err != nil {
		t.Fatalf("write src: %v", err)
	}
	enc := filepath.Join(dir, "a.enc")
	if err := encryptFile(src, enc, "right-pass"); err != nil {
		t.Fatalf("encryptFile: %v", err)
	}

	if err := decryptFile(enc, filepath.Join(dir, "x.tar"), "wrong-pass"); err == nil {
		t.Error("decrypt with wrong passphrase should fail, got nil")
	}

	// Flip a byte in the ciphertext body (after magic+salt+nonce) and expect a
	// GCM auth failure.
	raw, _ := os.ReadFile(enc)
	raw[len(raw)-1] ^= 0xff
	tampered := filepath.Join(dir, "tampered.enc")
	if err := os.WriteFile(tampered, raw, 0600); err != nil {
		t.Fatalf("write tampered: %v", err)
	}
	if err := decryptFile(tampered, filepath.Join(dir, "y.tar"), "right-pass"); err == nil {
		t.Error("decrypt of tampered ciphertext should fail, got nil")
	}
}
