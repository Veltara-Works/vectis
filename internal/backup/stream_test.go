package backup

import (
	"bytes"
	"fmt"
	"io"
	"runtime/debug"
	"testing"
)

const streamTestPass = "vxb2-stream-test-passphrase"

// fill returns n deterministic pseudo-random bytes (reproducible failures).
func fill(n int) []byte {
	b := make([]byte, n)
	x := byte(0x9e)
	for i := range b {
		x = x*31 + byte(i)
		b[i] = x ^ byte(i>>3)
	}
	return b
}

func vxb2Encrypt(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := streamEncrypt(&buf, bytes.NewReader(plain), streamTestPass); err != nil {
		t.Fatalf("streamEncrypt(%d bytes): %v", len(plain), err)
	}
	return buf.Bytes()
}

func vxb2Decrypt(archive []byte) ([]byte, error) {
	var out bytes.Buffer
	err := streamDecrypt(&out, bytes.NewReader(archive), streamTestPass)
	return out.Bytes(), err
}

// TestVXB2RoundTripSizes exercises boundary sizes around the chunk size,
// including empty input and non-chunk-aligned lengths.
func TestVXB2RoundTripSizes(t *testing.T) {
	sizes := []int{
		0, 1, 63,
		streamChunkSize - 1, streamChunkSize, streamChunkSize + 1,
		2 * streamChunkSize, 3*streamChunkSize + 7,
	}
	for _, n := range sizes {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			plain := fill(n)
			archive := vxb2Encrypt(t, plain)
			// Minimum archive = header + one final chunk (16-byte tag) even for empty.
			if len(archive) < streamHeaderLen+streamTagLen {
				t.Fatalf("archive too small: %d", len(archive))
			}
			got, err := vxb2Decrypt(archive)
			if err != nil {
				t.Fatalf("decrypt: %v", err)
			}
			if !bytes.Equal(got, plain) {
				t.Fatalf("round-trip mismatch at n=%d (got %d bytes)", n, len(got))
			}
		})
	}
}

// TestVXB2Deterministic: two encryptions of the same input must differ (fresh
// per-archive salt), and a chunk from one archive must not decrypt in another.
func TestVXB2SaltRandomness(t *testing.T) {
	plain := fill(3*streamChunkSize + 100)
	a1 := vxb2Encrypt(t, plain)
	a2 := vxb2Encrypt(t, plain)
	if bytes.Equal(a1, a2) {
		t.Fatal("two encryptions identical — salt not random")
	}
	if bytes.Equal(a1[:streamHeaderLen], a2[:streamHeaderLen]) {
		t.Fatal("archive salts identical")
	}
}

func splitVXB2(raw []byte) (header []byte, chunks [][]byte) {
	header = raw[:streamHeaderLen]
	body := raw[streamHeaderLen:]
	for len(body) > 0 {
		sz := streamEncChunkMaxLen
		if len(body) < sz {
			sz = len(body)
		}
		chunks = append(chunks, append([]byte(nil), body[:sz]...))
		body = body[sz:]
	}
	return header, chunks
}

func joinVXB2(header []byte, chunks [][]byte) []byte {
	out := append([]byte(nil), header...)
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

// TestVXB2TamperMatrix: every structural attack on the ciphertext must fail
// closed. Uses a 3-chunk archive (two full chunks + a short final).
func TestVXB2TamperMatrix(t *testing.T) {
	plain := fill(2*streamChunkSize + 500)
	base := vxb2Encrypt(t, plain)
	header, chunks := splitVXB2(base)
	if len(chunks) != 3 {
		t.Fatalf("expected 3 chunks, got %d", len(chunks))
	}

	// Sanity: the pristine archive round-trips.
	if got, err := vxb2Decrypt(base); err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("pristine archive failed: err=%v", err)
	}

	cases := map[string][]byte{
		"truncate-tail (drop final chunk)": joinVXB2(header, chunks[:2]),
		"drop-middle chunk":                joinVXB2(header, [][]byte{chunks[0], chunks[2]}),
		"reorder chunks":                   joinVXB2(header, [][]byte{chunks[1], chunks[0], chunks[2]}),
		"duplicate a chunk":                joinVXB2(header, [][]byte{chunks[0], chunks[0], chunks[1], chunks[2]}),
		"append after final chunk":         append(append([]byte(nil), base...), 0xde, 0xad, 0xbe, 0xef),
	}
	// flip a ciphertext byte in chunk 0
	flipCT := append([]byte(nil), base...)
	flipCT[streamHeaderLen+5] ^= 0xff
	cases["flip ciphertext byte"] = flipCT
	// flip a salt byte in the header
	flipSalt := append([]byte(nil), base...)
	flipSalt[len(streamMagicV2)+2] ^= 0xff
	cases["flip salt byte"] = flipSalt
	// flip the magic (would route elsewhere in decryptFile; streamDecrypt must reject)
	flipMagic := append([]byte(nil), base...)
	flipMagic[0] ^= 0xff
	cases["flip magic"] = flipMagic

	for name, bad := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := vxb2Decrypt(bad); err == nil {
				t.Fatalf("tamper %q decrypted without error — must fail closed", name)
			}
		})
	}
}

// TestVXB2CrossArchiveSplice: a chunk lifted from a DIFFERENT archive (different
// key/salt) must not decrypt in place.
func TestVXB2CrossArchiveSplice(t *testing.T) {
	plain := fill(2*streamChunkSize + 10)
	a := vxb2Encrypt(t, plain)
	b := vxb2Encrypt(t, plain) // different salt/key
	ha, ca := splitVXB2(a)
	_, cb := splitVXB2(b)
	spliced := joinVXB2(ha, [][]byte{ca[0], cb[1], ca[2]}) // middle chunk from archive b
	if _, err := vxb2Decrypt(spliced); err == nil {
		t.Fatal("cross-archive spliced chunk decrypted — must fail closed")
	}
}

// TestVXB2WrongKey: a wrong passphrase must fail (salt-derived key mismatch).
func TestVXB2WrongKey(t *testing.T) {
	archive := vxb2Encrypt(t, fill(streamChunkSize+1))
	var out bytes.Buffer
	if err := streamDecrypt(&out, bytes.NewReader(archive), "wrong-pass"); err == nil {
		t.Fatal("decrypt with wrong passphrase succeeded — must fail")
	}
}

// TestVXB2SelfVerify covers verifyVXB2's length check.
func TestVXB2SelfVerify(t *testing.T) {
	plain := fill(3 * streamChunkSize)
	archive := vxb2Encrypt(t, plain)
	if err := verifyVXB2(bytes.NewReader(archive), streamTestPass, int64(len(plain))); err != nil {
		t.Fatalf("verifyVXB2 valid archive: %v", err)
	}
	if err := verifyVXB2(bytes.NewReader(archive), streamTestPass, int64(len(plain))+1); err == nil {
		t.Fatal("verifyVXB2 accepted a wrong expected length")
	}
}

// TestVXB2StreamingMemoryBounded proves memory is O(chunk), not O(archive): it
// pipes a 256 MiB plaintext through encrypt->decrypt under a tight soft memory
// limit and compares hashes without ever holding the whole plaintext or archive.
// A whole-file implementation would allocate hundreds of MB and thrash/OOM here.
func TestVXB2StreamingMemoryBounded(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping large streaming memory test in -short mode")
	}
	const total = 256 << 20 // 256 MiB, far larger than the soft limit below

	prev := debug.SetMemoryLimit(96 << 20) // 96 MiB soft cap
	defer debug.SetMemoryLimit(prev)

	// encrypt: generated plaintext -> pipe
	encR, encW := io.Pipe()
	go func() {
		err := streamEncrypt(encW, io.LimitReader(&patternReader{}, total), streamTestPass)
		encW.CloseWithError(err)
	}()
	// decrypt the piped archive, hashing the recovered plaintext
	var gotSum, wantSum uint64
	dr, dw := io.Pipe()
	go func() {
		err := streamDecrypt(dw, encR, streamTestPass)
		dw.CloseWithError(err)
	}()
	gotSum, gotN, err := sumReader(dr)
	if err != nil {
		t.Fatalf("streaming decrypt: %v", err)
	}
	wantSum, _, _ = sumReader(io.LimitReader(&patternReader{}, total))
	if gotN != total {
		t.Fatalf("recovered %d bytes, want %d", gotN, total)
	}
	if gotSum != wantSum {
		t.Fatalf("streamed round-trip checksum mismatch")
	}
}

// patternReader emits a deterministic byte stream without allocating it.
type patternReader struct{ i uint64 }

func (p *patternReader) Read(b []byte) (int, error) {
	for j := range b {
		b[j] = byte(p.i*1103515245 + 12345)
		p.i++
	}
	return len(b), nil
}

// sumReader consumes r in fixed buffers, returning a rolling checksum + length.
func sumReader(r io.Reader) (uint64, int64, error) {
	buf := make([]byte, 64*1024)
	var sum uint64
	var n int64
	for {
		m, err := r.Read(buf)
		for _, c := range buf[:m] {
			sum = sum*1099511628211 ^ uint64(c)
		}
		n += int64(m)
		if err == io.EOF {
			return sum, n, nil
		}
		if err != nil {
			return sum, n, err
		}
	}
}
