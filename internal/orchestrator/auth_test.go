package orchestrator

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRequireAuthConfigured is the E-H1 boot guard: the orchestrator must refuse
// to start when neither a bearer token nor mTLS is configured, rather than serve
// a fail-open control plane.
func TestRequireAuthConfigured(t *testing.T) {
	if err := (&Server{}).requireAuthConfigured(); err == nil {
		t.Fatal("expected refuse-to-boot error with no token and no mTLS")
	}
	if err := (&Server{token: "secret"}).requireAuthConfigured(); err != nil {
		t.Fatalf("unexpected error with a token configured: %v", err)
	}
}

// TestAuthMiddleware_EmptyTokenFailsClosed is the E-H1 request-path guard: with
// no configured token (and no mTLS), no request authenticates — in particular an
// empty presented bearer ("Bearer ") must not ConstantTimeCompare-equal the
// empty configured token.
func TestAuthMiddleware_EmptyTokenFailsClosed(t *testing.T) {
	s := &Server{} // token == "" and tlsConfig == nil
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("handler reached: empty configured token authenticated a request")
	})
	h := s.authMiddleware(next)

	for _, authHdr := range []string{"", "Bearer ", "Bearer anything"} {
		r := httptest.NewRequest(http.MethodPost, "/internal/apply", nil)
		if authHdr != "" {
			r.Header.Set("Authorization", authHdr)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, r)
		if rr.Code == http.StatusOK {
			t.Fatalf("Authorization=%q: got 200, want rejection", authHdr)
		}
	}
}

// TestAuthMiddleware_MatchingTokenPasses confirms a correctly configured token
// still authenticates a matching bearer (no regression from the fail-closed fix).
func TestAuthMiddleware_MatchingTokenPasses(t *testing.T) {
	s := &Server{token: "s3cret"}
	passed := false
	h := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passed = true
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "/internal/apply", nil)
	r.Header.Set("Authorization", "Bearer s3cret")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, r)
	if !passed || rr.Code != http.StatusOK {
		t.Fatalf("matching token rejected: passed=%v code=%d", passed, rr.Code)
	}
}
