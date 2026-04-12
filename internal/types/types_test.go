package types

import (
	"strings"
	"testing"
)

func TestNewUUIDv7_Format(t *testing.T) {
	id := NewUUIDv7()
	if len(id) != 36 {
		t.Fatalf("expected 36-char UUID string, got %d: %q", len(id), id)
	}
	if id[8] != '-' || id[13] != '-' || id[18] != '-' || id[23] != '-' {
		t.Errorf("malformed UUID: %q", id)
	}
}

func TestNewUUIDv7_Unique(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for i := 0; i < 100; i++ {
		id := NewUUIDv7()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate UUID after %d iterations: %s", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestNewVerificationToken(t *testing.T) {
	tok := NewVerificationToken()
	if !strings.HasPrefix(tok, "vectis-verify=") {
		t.Errorf("token should start with vectis-verify=, got %q", tok[:20])
	}
	// 32 bytes hex = 64 chars + prefix
	if len(tok) != len("vectis-verify=")+64 {
		t.Errorf("unexpected token length: %d", len(tok))
	}
}

func TestNewVerificationToken_Unique(t *testing.T) {
	t1 := NewVerificationToken()
	t2 := NewVerificationToken()
	if t1 == t2 {
		t.Error("two tokens should differ")
	}
}

func TestNewSuccessResponse(t *testing.T) {
	resp := NewSuccessResponse("hello", "req-1")
	if resp.Data != "hello" {
		t.Errorf("data = %v, want hello", resp.Data)
	}
	if resp.Error != nil {
		t.Error("success response should have nil error")
	}
	if resp.Meta.RequestID != "req-1" {
		t.Errorf("request_id = %q, want req-1", resp.Meta.RequestID)
	}
	if resp.Meta.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
}

func TestNewErrorResponse(t *testing.T) {
	resp := NewErrorResponse("NOT_FOUND", "resource not found", "req-2")
	if resp.Data != nil {
		t.Errorf("error response should have nil data, got %v", resp.Data)
	}
	if resp.Error == nil {
		t.Fatal("error response should have non-nil error")
	}
	if resp.Error.Code != "NOT_FOUND" {
		t.Errorf("code = %q, want NOT_FOUND", resp.Error.Code)
	}
	if resp.Error.Message != "resource not found" {
		t.Errorf("message = %q", resp.Error.Message)
	}
	if resp.Meta.RequestID != "req-2" {
		t.Errorf("request_id = %q, want req-2", resp.Meta.RequestID)
	}
}
