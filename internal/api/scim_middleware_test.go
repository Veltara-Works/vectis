package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Veltara-Works/vectis/internal/repository"
)

// stubSCIMStore implements scimTokenStore without a database.
type stubSCIMStore struct {
	tok *repository.SCIMToken
	err error
}

func (s *stubSCIMStore) GetByHash(ctx context.Context, hash string) (*repository.SCIMToken, error) {
	return s.tok, s.err
}
func (s *stubSCIMStore) TouchLastUsed(ctx context.Context, id string) {}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

const validRawSCIM = "scim_" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestSCIMAuthMiddleware_Valid(t *testing.T) {
	store := &stubSCIMStore{tok: &repository.SCIMToken{ID: "tok-123", Active: true}}

	var seenTokenID string
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		if v, ok := r.Context().Value(ctxSCIMTokenID).(string); ok {
			seenTokenID = v
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
	req.Header.Set("Authorization", "Bearer "+validRawSCIM)
	rr := httptest.NewRecorder()
	scimAuthMiddleware(store, quietLogger())(next).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rr.Code)
	}
	if !called {
		t.Fatal("next handler was not called for a valid token")
	}
	if seenTokenID != "tok-123" {
		t.Errorf("ctxSCIMTokenID = %q, want %q", seenTokenID, "tok-123")
	}
}

func TestSCIMAuthMiddleware_Rejects(t *testing.T) {
	cases := []struct {
		name       string
		authHeader string // "" = omit header
		store      *stubSCIMStore
		wantStatus int
	}{
		{"missing header", "", &stubSCIMStore{}, http.StatusUnauthorized},
		{"not bearer", "Token " + validRawSCIM, &stubSCIMStore{}, http.StatusUnauthorized},
		{"wrong prefix (api key)", "Bearer vectis_abc123", &stubSCIMStore{}, http.StatusUnauthorized},
		{"unknown/revoked/expired", "Bearer " + validRawSCIM, &stubSCIMStore{tok: nil}, http.StatusUnauthorized},
		{"store error", "Bearer " + validRawSCIM, &stubSCIMStore{err: errors.New("db down")}, http.StatusInternalServerError},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

			req := httptest.NewRequest(http.MethodGet, "/scim/v2/Users", nil)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			rr := httptest.NewRecorder()
			scimAuthMiddleware(tc.store, quietLogger())(next).ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tc.wantStatus)
			}
			if called {
				t.Error("next handler must not run on auth failure")
			}
			// Errors must be SCIM-shaped, not the Vectis envelope.
			if ct := rr.Header().Get("Content-Type"); ct != scimContentType {
				t.Errorf("Content-Type = %q, want %q", ct, scimContentType)
			}
			var body scimError
			if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
				t.Fatalf("error body is not valid JSON: %v", err)
			}
			if len(body.Schemas) != 1 || body.Schemas[0] != scimErrorSchema {
				t.Errorf("schemas = %v, want [%q]", body.Schemas, scimErrorSchema)
			}
			if body.Status != strings.TrimSpace(itoa(tc.wantStatus)) {
				t.Errorf("status field = %q, want %q (string)", body.Status, itoa(tc.wantStatus))
			}
		})
	}
}

// itoa avoids importing strconv twice; mirrors writeSCIMError's encoding.
func itoa(n int) string {
	switch n {
	case http.StatusUnauthorized:
		return "401"
	case http.StatusInternalServerError:
		return "500"
	default:
		return ""
	}
}
