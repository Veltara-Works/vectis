package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/Veltara-Works/vectis/internal/auth"
)

// TestDomainInScope locks the API-key domain-scoping decision used by
// canAccessDomain: an empty scope list = unscoped (all domains), otherwise the
// domain must be explicitly listed. This is the control that stops a
// domain-scoped key from reaching other domains' resources.
func TestDomainInScope(t *testing.T) {
	cases := []struct {
		name   string
		scoped []string
		domain string
		want   bool
	}{
		{"empty scope = all domains", nil, "d1", true},
		{"empty slice = all domains", []string{}, "d1", true},
		{"listed domain allowed", []string{"d1", "d2"}, "d2", true},
		{"unlisted domain denied", []string{"d1", "d2"}, "d3", false},
		{"single scope match", []string{"d1"}, "d1", true},
		{"single scope mismatch", []string{"d1"}, "d2", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domainInScope(tc.scoped, tc.domain); got != tc.want {
				t.Fatalf("domainInScope(%v, %q) = %v, want %v", tc.scoped, tc.domain, got, tc.want)
			}
		})
	}
}

// scopeCtx builds a request context mirroring what authMiddleware stashes: an
// admin role and, for API-key principals, the key id + ScopedDomainIDs. A nil
// keyScope means session auth (no key); a non-nil (incl. empty) slice means an
// API key with that scope.
func scopeCtx(role string, keyScope []string) context.Context {
	ctx := context.WithValue(context.Background(), ctxAdminRole, role)
	if keyScope != nil {
		ctx = context.WithValue(ctx, ctxAPIKeyID, "key-1")
		ctx = context.WithValue(ctx, ctxAPIKeyScope, keyScope)
	}
	return ctx
}

// TestIntersectDomainIDs locks the R3 set-intersection helper: the result is
// always a non-nil explicit allow-list (empty = no access), never nil ("all").
func TestIntersectDomainIDs(t *testing.T) {
	cases := []struct {
		name string
		a, b []string
		want []string
	}{
		{"overlap", []string{"d1", "d2", "d3"}, []string{"d2", "d3", "d4"}, []string{"d2", "d3"}},
		{"disjoint = empty", []string{"d1"}, []string{"d2"}, []string{}},
		{"empty a", []string{}, []string{"d1"}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := intersectDomainIDs(tc.a, tc.b)
			if got == nil {
				t.Fatalf("intersectDomainIDs must never return nil")
			}
			if len(got) != len(tc.want) {
				t.Fatalf("intersectDomainIDs(%v,%v) = %v, want %v", tc.a, tc.b, got, tc.want)
			}
			set := map[string]bool{}
			for _, x := range got {
				set[x] = true
			}
			for _, x := range tc.want {
				if !set[x] {
					t.Fatalf("intersectDomainIDs(%v,%v) = %v, missing %q", tc.a, tc.b, got, x)
				}
			}
		})
	}
}

// TestGetAllowedDomainIDs_KeyScopeClamp is the R3 regression net: a scoped API
// key owned by an admin (role grants all domains) must NOT resolve to nil
// ("all domains") on the no-domain_id aggregate path — it must clamp to the
// key's ScopedDomainIDs. This is the exact #119 / code-review-ultra Root-B leak.
func TestGetAllowedDomainIDs_KeyScopeClamp(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name     string
		role     string
		keyScope []string
		wantNil  bool     // nil = unrestricted (all domains)
		wantSet  []string // when not nil
	}{
		{"session admin = all domains", auth.RoleAdmin, nil, true, nil},
		{"unscoped key admin = all domains", auth.RoleAdmin, []string{}, true, nil},
		{"scoped key admin clamps to key scope", auth.RoleAdmin, []string{"d1"}, false, []string{"d1"}},
		{"scoped key super_admin clamps too", auth.RoleSuperAdmin, []string{"d1", "d2"}, false, []string{"d1", "d2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := s.getAllowedDomainIDs(scopeCtx(tc.role, tc.keyScope))
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil (all domains), got %v", got)
				}
				return
			}
			if len(got) != len(tc.wantSet) {
				t.Fatalf("getAllowedDomainIDs = %v, want %v", got, tc.wantSet)
			}
		})
	}
}

// TestRequireDomainAccess is the R1 regression net: the /domains/{domainID}
// choke point must 403 a key scoped to a different domain and pass one scoped to
// the requested domain — even though the owning role grants all domains.
func TestRequireDomainAccess(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name        string
		keyScope    []string
		urlDomainID string
		wantStatus  int
	}{
		{"scoped key, in-scope domain → allowed", []string{"d1"}, "d1", http.StatusOK},
		{"scoped key, out-of-scope domain → 403", []string{"d1"}, "d2", http.StatusForbidden},
		{"unscoped key → allowed", []string{}, "d2", http.StatusOK},
		{"session (no key) → allowed", nil, "d2", http.StatusOK},
		{"missing domainID → 403", []string{"d1"}, "", http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextCalled := false
			h := s.requireDomainAccess(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled = true
				w.WriteHeader(http.StatusOK)
			}))

			r := httptest.NewRequest(http.MethodPost, "/api/v1/domains/"+tc.urlDomainID+"/verify", nil)
			ctx := scopeCtx(auth.RoleAdmin, tc.keyScope)
			rctx := chi.NewRouteContext()
			rctx.URLParams.Add("domainID", tc.urlDomainID)
			ctx = context.WithValue(ctx, chi.RouteCtxKey, rctx)
			r = r.WithContext(ctx)

			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, r)

			if rr.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d", rr.Code, tc.wantStatus)
			}
			if wantAllowed := tc.wantStatus == http.StatusOK; nextCalled != wantAllowed {
				t.Fatalf("nextCalled = %v, want %v", nextCalled, wantAllowed)
			}
		})
	}
}
