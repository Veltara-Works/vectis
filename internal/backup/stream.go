package backup

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// VXB2 is the streaming, chunked-AEAD backup archive format. It replaces the
// whole-file VXB1 layout (magic||salt||nonce||ciphertext) whose encrypt/decrypt
// buffered the ENTIRE archive (+ a full-size Seal/Open copy) in RAM — ~2x the
// archive size — which OOM-killed the API container mid-backup once a maildir
// grew past a few hundred MB (mx1, 2026-06-24, silent 9-night failure). VXB2
// encrypts and decrypts in O(chunk) memory regardless of archive size.
//
// Wire format:
//
//	magic  "VXB2"            4 bytes
//	salt                    16 bytes (CSPRNG; Argon2id salt)
//	chunk[0] chunk[1] ...    each = AES-256-GCM(ciphertext) || 16-byte tag
//
//	header = magic||salt (20 bytes) is the GCM AAD on EVERY chunk, so magic+salt
//	are authenticated without a separate MAC (a flipped salt fails both the key
//	derivation and the AAD).
//
// Per-chunk nonce (12 bytes) = counter(11 big-endian) || finalFlag(1). The
// counter (chunk index from 0) binds each chunk to its position — defeating
// reorder/duplication — and the finalFlag (0x01 only on the last chunk) plus the
// decrypt rule "the final-flag chunk must coincide with EOF" defeats
// truncation/append. Even empty input emits exactly one authenticated final
// chunk (a bare 16-byte tag), so there are no zero-chunk archives.
//
// Nonce-reuse safety: each archive derives a UNIQUE key from a fresh random salt
// (deriveKeyArgon2), so a counter starting at 0 never collides across archives.
// INVARIANT: never cache/reuse a derived key across archives.
const (
	streamMagicV2   = "VXB2"
	streamChunkSize = 1 << 20 // 1 MiB plaintext per chunk (pinned; NOT read from header)
	streamNonceLen  = 12      // AES-GCM standard nonce
	streamTagLen    = 16      // AES-GCM tag

	// legacyWholeFileMax caps the whole-file VXB1/legacy decrypt path (which is
	// un-streamable and allocates ~2x the file). Without it, a bit-flip of a
	// large VXB2 archive's magic (VXB2->VXB1) would route it to the 2x-RAM path
	// = OOM DoS. No legitimate large legacy archive exists; a genuine large
	// legacy restore uses the host CLI (no cgroup) with the override env.
	legacyWholeFileMax   = 256 << 20 // 256 MiB
	allowLargeLegacyEnv  = "VECTIS_ALLOW_LARGE_LEGACY_RESTORE"
	streamHeaderLen      = len(streamMagicV2) + backupSaltLen // 20
	streamEncChunkMaxLen = streamChunkSize + streamTagLen
)

// chunkNonce builds the 12-byte nonce for chunk `counter`. Bytes [3:11] hold the
// counter big-endian (bytes [0:3] stay zero, giving an 11-byte counter space),
// and byte [11] is the final flag.
func chunkNonce(counter uint64, final bool) []byte {
	n := make([]byte, streamNonceLen)
	binary.BigEndian.PutUint64(n[3:11], counter)
	if final {
		n[11] = 1
	}
	return n
}

// newGCM derives the per-archive key from passphrase+salt and returns an AES-256-GCM AEAD.
func newGCM(passphrase string, salt []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(deriveKeyArgon2(passphrase, salt))
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create GCM: %w", err)
	}
	if gcm.NonceSize() != streamNonceLen {
		return nil, fmt.Errorf("unexpected GCM nonce size %d", gcm.NonceSize())
	}
	return gcm, nil
}

// streamEncrypt reads plaintext from src and writes a VXB2 archive to dst in
// O(chunk) memory. It never buffers the whole input.
func streamEncrypt(dst io.Writer, src io.Reader, passphrase string) error {
	salt := make([]byte, backupSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return fmt.Errorf("generate salt: %w", err)
	}
	gcm, err := newGCM(passphrase, salt)
	if err != nil {
		return err
	}
	header := append([]byte(streamMagicV2), salt...)
	if _, err := dst.Write(header); err != nil {
		return fmt.Errorf("write header: %w", err)
	}

	br := bufio.NewReaderSize(src, 128*1024)
	buf := make([]byte, streamChunkSize)
	sealed := make([]byte, 0, streamEncChunkMaxLen)
	var counter uint64
	for {
		n, rerr := io.ReadFull(br, buf)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return fmt.Errorf("read plaintext: %w", rerr)
		}
		final := rerr == io.EOF || rerr == io.ErrUnexpectedEOF
		if !final {
			// Full chunk read; peek one byte to learn whether any data follows.
			if _, perr := br.Peek(1); perr != nil {
				if perr == io.EOF {
					final = true
				} else {
					return fmt.Errorf("peek: %w", perr)
				}
			}
		}
		sealed = gcm.Seal(sealed[:0], chunkNonce(counter, final), buf[:n], header)
		if _, werr := dst.Write(sealed); werr != nil {
			return fmt.Errorf("write chunk %d: %w", counter, werr)
		}
		if final {
			return nil
		}
		counter++
		if counter == 0 {
			return errors.New("chunk counter overflow")
		}
	}
}

// streamDecrypt reads a VXB2 archive from src (positioned at the start) and
// writes the plaintext to dst in O(chunk) memory. It fails closed on any tag
// failure, on a truncated tail (EOF before a final-flag chunk), and on data
// after the final-flag chunk (append/splice).
func streamDecrypt(dst io.Writer, src io.Reader, passphrase string) error {
	header := make([]byte, streamHeaderLen)
	if _, err := io.ReadFull(src, header); err != nil {
		return fmt.Errorf("read header: %w", err)
	}
	if string(header[:len(streamMagicV2)]) != streamMagicV2 {
		return errors.New("not a VXB2 archive")
	}
	salt := header[len(streamMagicV2):]
	gcm, err := newGCM(passphrase, salt)
	if err != nil {
		return err
	}

	br := bufio.NewReaderSize(src, 128*1024)
	enc := make([]byte, streamEncChunkMaxLen)
	plain := make([]byte, 0, streamChunkSize)
	var counter uint64
	for {
		n, rerr := io.ReadFull(br, enc)
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return fmt.Errorf("read chunk %d: %w", counter, rerr)
		}
		if rerr == io.EOF && n == 0 {
			// Ran out of data without ever decrypting a final-flag chunk.
			return errors.New("truncated archive: missing final chunk")
		}
		if n < streamTagLen {
			return errors.New("truncated archive: short trailing chunk")
		}
		final := rerr == io.ErrUnexpectedEOF
		if !final {
			if _, perr := br.Peek(1); perr != nil {
				if perr == io.EOF {
					final = true
				} else {
					return fmt.Errorf("peek: %w", perr)
				}
			}
		}
		pt, oerr := gcm.Open(plain[:0], chunkNonce(counter, final), enc[:n], header)
		if oerr != nil {
			return fmt.Errorf("decrypt chunk %d (final=%v) failed — tampered, truncated, or wrong key: %w", counter, final, oerr)
		}
		if _, werr := dst.Write(pt); werr != nil {
			return fmt.Errorf("write plaintext: %w", werr)
		}
		if final {
			// Defense in depth: nothing may follow a final chunk.
			if _, perr := br.Peek(1); perr != io.EOF {
				return errors.New("trailing data after final chunk")
			}
			return nil
		}
		counter++
		if counter == 0 {
			return errors.New("chunk counter overflow")
		}
	}
}

// countingWriter counts bytes written and discards them.
type countingWriter struct{ n int64 }

func (c *countingWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// verifyVXB2 stream-decrypts a freshly written VXB2 archive to a discard sink,
// asserting it decrypts cleanly (all tags valid, final flag coincides with EOF)
// and that the recovered length equals wantPlaintextLen. Called at create time
// BEFORE the plaintext is deleted, so a corrupt/unverifiable archive is a failed
// backup rather than an undetected data-loss.
func verifyVXB2(src io.Reader, passphrase string, wantPlaintextLen int64) error {
	cw := &countingWriter{}
	if err := streamDecrypt(cw, src, passphrase); err != nil {
		return fmt.Errorf("archive self-verify decrypt: %w", err)
	}
	if cw.n != wantPlaintextLen {
		return fmt.Errorf("archive self-verify length mismatch: decrypted %d, expected %d", cw.n, wantPlaintextLen)
	}
	return nil
}
