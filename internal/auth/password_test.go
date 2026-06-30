package auth

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	hash, err := HashPassword("my-secure-password")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if !strings.HasPrefix(hash, "$argon2id$") {
		t.Errorf("hash should start with $argon2id$, got: %s", hash[:20])
	}

	ok, err := VerifyPassword("my-secure-password", hash)
	if err != nil || !ok {
		t.Fatalf("verify correct password: ok=%v err=%v", ok, err)
	}

	ok, err = VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("verify wrong password error: %v", err)
	}
	if ok {
		t.Fatal("wrong password should not verify")
	}
}

func TestHashUniqueness(t *testing.T) {
	h1, _ := HashPassword("same-password")
	h2, _ := HashPassword("same-password")
	if h1 == h2 {
		t.Error("two hashes of the same password should differ (different salts)")
	}
}

func TestVerifyInvalidFormat(t *testing.T) {
	_, err := VerifyPassword("anything", "not-a-valid-hash")
	if err == nil {
		t.Error("expected error for invalid hash format")
	}
}

// TestDummyPasswordHashWellFormed is the regression guard for the
// user-enumeration timing fix (#179): the unknown-account login path verifies
// against dummyPasswordHash to do the same Argon2id work a real verify does, so
// the dummy hash MUST be a well-formed, standard-param Argon2id hash. If it were
// malformed, VerifyPassword would bail early (parse error) and skip the KDF,
// re-opening the timing side channel. We assert it parses cleanly with the same
// params HashPassword emits, and that it never authenticates a caller password.
func TestDummyPasswordHashWellFormed(t *testing.T) {
	if !strings.HasPrefix(dummyPasswordHash, "$argon2id$") {
		t.Fatalf("dummy hash is not argon2id: %.20q", dummyPasswordHash)
	}
	// Standard params (m=64MB, t=3, p=4) — must match HashPassword so the dummy
	// verify costs the same as a real one.
	if !strings.Contains(dummyPasswordHash, "$m=65536,t=3,p=4$") {
		t.Errorf("dummy hash uses non-standard params: %q", dummyPasswordHash)
	}
	// A well-formed hash makes VerifyPassword run the full KDF and return
	// (false, nil) for an arbitrary login password — no parse error (which would
	// short-circuit and skip the KDF, re-leaking timing). The dummy's own fixed
	// plaintext is not tested here: it would legitimately match, but that's
	// harmless because VerifyDummyPassword discards the result and the
	// unknown-account path returns 401 regardless.
	for _, pw := range []string{"", "password", "another-guess", "totally-unrelated-input"} {
		ok, err := VerifyPassword(pw, dummyPasswordHash)
		if err != nil {
			t.Errorf("VerifyPassword(%q, dummy) errored (would skip KDF, leaking timing): %v", pw, err)
		}
		if ok {
			t.Errorf("dummy hash matched an arbitrary login password %q", pw)
		}
	}
}

// TestVerifyDummyPasswordRuns is a smoke test that the exported equalizer is
// callable and side-effect-free for any input (it discards its result).
func TestVerifyDummyPasswordRuns(t *testing.T) {
	VerifyDummyPassword("")
	VerifyDummyPassword("some-password-guess")
}
