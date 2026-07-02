package api

import "testing"

// TestClickToken_BindsURL locks the D-M2 open-redirect fix: a click token is
// HMAC'd over the message ID AND the exact redirect URL, so a token minted for
// one link cannot be reused to redirect anywhere else.
func TestClickToken_BindsURL(t *testing.T) {
	s := &Server{internalToken: "test-secret"}
	const msgID = "msg-123@mail.example.com"
	const good = "https://example.com/landing?a=1"

	tok := s.GenerateClickToken(msgID, good)

	// Round-trips for the exact URL it was signed for.
	if id, ok := s.verifyClickToken(tok, good); !ok || id != msgID {
		t.Fatalf("valid token+url should verify: ok=%v id=%q", ok, id)
	}

	// The same token must NOT authorize a different destination.
	if _, ok := s.verifyClickToken(tok, "https://evil.example/phish"); ok {
		t.Fatal("token reused for a different url must be rejected (open redirect)")
	}

	// Any tampering with the url query param fails verification.
	if _, ok := s.verifyClickToken(tok, good+"&extra=1"); ok {
		t.Fatal("token must not verify against a mutated url")
	}
}

// TestClickToken_NotInterchangeableWithOpenToken ensures the domain separator
// keeps the two token families distinct: an open-pixel token (message ID only)
// can't be replayed as a click token to gain an open redirect, and vice versa.
func TestClickToken_NotInterchangeableWithOpenToken(t *testing.T) {
	s := &Server{internalToken: "test-secret"}
	const msgID = "msg-abc@mail.example.com"
	const dest = "https://example.com/x"

	openTok := s.GenerateTrackingToken(msgID)
	if _, ok := s.verifyClickToken(openTok, dest); ok {
		t.Fatal("open token must not be accepted as a click token")
	}

	clickTok := s.GenerateClickToken(msgID, dest)
	if _, ok := s.verifyTrackingToken(clickTok); ok {
		t.Fatal("click token must not be accepted as an open token")
	}
}
