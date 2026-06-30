package api

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"testing"

	"github.com/Veltara-Works/vectis/internal/repository"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// TestResolveFederatedAdmin is the regression for the #159 dedup and the #117/172
// verified-email parity. It exercises the security-critical resolution paths that
// run before any repository.GetByEmail call (the auto-link success path needs the
// integration harness). The getBySubject/link closures are injected, so no DB.
func TestResolveFederatedAdmin(t *testing.T) {
	ctx := context.Background()

	// newLinker builds a federatedLinker whose link() flips *linked so tests can
	// assert it was (not) called.
	newLinker := func(getBySubject func(context.Context, string, string) (*repository.Admin, error), linked *bool) federatedLinker {
		return federatedLinker{
			codePrefix:   "OIDC",
			logLabel:     "oidc",
			getBySubject: getBySubject,
			link: func(context.Context, string, string, string) error {
				if linked != nil {
					*linked = true
				}
				return nil
			},
			unverifiedMsg: "unverified",
			noAccountMsg:  "no account",
		}
	}

	t.Run("already linked returns admin without linking", func(t *testing.T) {
		s := &Server{logger: discardLogger()}
		linked := false
		fl := newLinker(func(context.Context, string, string) (*repository.Admin, error) {
			return &repository.Admin{ID: "a1"}, nil
		}, &linked)
		// EmailVerified deliberately false: an already-linked subject must not be
		// subject to the email-trust gate.
		admin, out := s.resolveFederatedAdmin(ctx, federatedIdentity{Provider: "p", Subject: "s", EmailVerified: false}, fl)
		if out.code != "" {
			t.Fatalf("code = %q, want success", out.code)
		}
		if admin == nil || admin.ID != "a1" {
			t.Fatalf("admin = %+v, want id a1", admin)
		}
		if linked {
			t.Error("link() called for an already-linked subject")
		}
	})

	t.Run("subject lookup error is INTERNAL_ERROR", func(t *testing.T) {
		s := &Server{logger: discardLogger()}
		fl := newLinker(func(context.Context, string, string) (*repository.Admin, error) {
			return nil, errors.New("db down")
		}, nil)
		admin, out := s.resolveFederatedAdmin(ctx, federatedIdentity{Provider: "p", Subject: "s"}, fl)
		if admin != nil || out.code != "INTERNAL_ERROR" || out.httpStatus != http.StatusInternalServerError {
			t.Fatalf("got admin=%v out=%+v, want INTERNAL_ERROR 500", admin, out)
		}
	})

	t.Run("unverified email refuses auto-link (OIDC #117)", func(t *testing.T) {
		s := &Server{logger: discardLogger()}
		linked := false
		fl := newLinker(func(context.Context, string, string) (*repository.Admin, error) {
			return nil, nil // not linked by subject → email fallback
		}, &linked)
		admin, out := s.resolveFederatedAdmin(ctx, federatedIdentity{
			Provider: "p", Subject: "s", Email: "victim@example.com", EmailVerified: false,
		}, fl)
		if admin != nil || out.code != "OIDC_EMAIL_UNVERIFIED" || out.httpStatus != http.StatusForbidden {
			t.Fatalf("out = %+v, want OIDC_EMAIL_UNVERIFIED 403", out)
		}
		if linked {
			t.Error("link() called despite unverified email")
		}
	})

	t.Run("verified but malformed email refuses auto-link", func(t *testing.T) {
		s := &Server{logger: discardLogger()}
		fl := newLinker(func(context.Context, string, string) (*repository.Admin, error) {
			return nil, nil
		}, nil)
		for _, bad := range []string{"", "   ", "no-at-symbol", "@no-local.com", "trailing@"} {
			admin, out := s.resolveFederatedAdmin(ctx, federatedIdentity{
				Provider: "p", Subject: "s", Email: bad, EmailVerified: true,
			}, fl)
			if admin != nil || out.code != "OIDC_EMAIL_UNVERIFIED" || out.httpStatus != http.StatusForbidden {
				t.Errorf("email %q: out = %+v, want OIDC_EMAIL_UNVERIFIED 403", bad, out)
			}
		}
	})

	t.Run("saml signed assertion still rejects an empty asserted email (#172 hardening)", func(t *testing.T) {
		s := &Server{logger: discardLogger()}
		fl := newLinker(func(context.Context, string, string) (*repository.Admin, error) {
			return nil, nil
		}, nil)
		fl.codePrefix = "SAML"
		fl.logLabel = "saml"
		// SAML sets EmailVerified=true (signed assertion), but an empty/malformed
		// asserted address must still never be auto-linked.
		admin, out := s.resolveFederatedAdmin(ctx, federatedIdentity{
			Provider: "p", Subject: "s", Email: "", EmailVerified: true,
		}, fl)
		if admin != nil || out.code != "SAML_EMAIL_UNVERIFIED" || out.httpStatus != http.StatusForbidden {
			t.Fatalf("out = %+v, want SAML_EMAIL_UNVERIFIED 403", out)
		}
	})
}

// TestIsLinkableEmail pins the auto-link key guard: both a local part and a
// domain must be present for an address to be trusted as a link key.
func TestIsLinkableEmail(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"ian@example.com", true},
		{"a@b.co", true},
		{"", false},
		{"no-at", false},
		{"@nodomain.com", false},
		{"nolocal@", false},
	}
	for _, tt := range tests {
		if got := isLinkableEmail(tt.in); got != tt.want {
			t.Errorf("isLinkableEmail(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}
