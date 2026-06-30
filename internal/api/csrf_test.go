package api

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Veltara-Works/vectis/internal/config"
)

func TestIsSafeMethod(t *testing.T) {
	safe := []string{http.MethodGet, http.MethodHead, http.MethodOptions, http.MethodTrace}
	unsafe := []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}
	for _, m := range safe {
		if !isSafeMethod(m) {
			t.Errorf("isSafeMethod(%q) = false, want true", m)
		}
	}
	for _, m := range unsafe {
		if isSafeMethod(m) {
			t.Errorf("isSafeMethod(%q) = true, want false", m)
		}
	}
}

func TestRequestOriginHost(t *testing.T) {
	cases := []struct {
		name   string
		origin string
		refer  string
		want   string
	}{
		{"origin host", "https://mail.example.com", "", "mail.example.com"},
		{"origin with port stripped", "https://mail.example.com:8443", "", "mail.example.com"},
		{"referer fallback", "", "https://mail.example.com/admin/", "mail.example.com"},
		{"origin wins over referer", "https://a.example", "https://b.example/x", "a.example"},
		{"null origin has no host", "null", "", ""},
		{"neither present", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://mail.example.com/api/v1/x", nil)
			r.Header.Del("Origin")
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if c.refer != "" {
				r.Header.Set("Referer", c.refer)
			}
			if got := requestOriginHost(r); got != c.want {
				t.Errorf("requestOriginHost() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestCSRFProtect exercises the middleware end-to-end through a stub next handler.
func TestCSRFProtect(t *testing.T) {
	s := &Server{cfg: &config.VectisConfig{Hostname: "mail.example.com"}}
	pass := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pass = true
		w.WriteHeader(http.StatusOK)
	})
	h := s.csrfProtect(next)

	withCookie := func(r *http.Request) *http.Request {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "session-token"})
		return r
	}

	cases := []struct {
		name       string
		method     string
		cookie     bool
		origin     string
		referer    string
		host       string // overrides request Host when non-empty
		wantPass   bool
		wantStatus int
	}{
		{"safe GET bypasses even cross-origin", http.MethodGet, true, "https://evil.example", "", "", true, http.StatusOK},
		{"POST no cookie (bearer/api-key) bypasses", http.MethodPost, false, "https://evil.example", "", "", true, http.StatusOK},
		{"POST cookie same-origin allowed", http.MethodPost, true, "https://mail.example.com", "", "", true, http.StatusOK},
		{"POST cookie cross-origin rejected", http.MethodPost, true, "https://evil.example", "", "", false, http.StatusForbidden},
		{"POST cookie no origin/referer defers to SameSite", http.MethodPost, true, "", "", "", true, http.StatusOK},
		{"POST cookie referer fallback allowed", http.MethodPost, true, "", "https://mail.example.com/admin/", "", true, http.StatusOK},
		{"POST cookie matches configured hostname when Host differs", http.MethodPost, true, "https://mail.example.com", "", "internal-backend:8080", true, http.StatusOK},
		{"POST cookie null origin rejected", http.MethodPost, true, "null", "", "", false, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pass = false
			r := httptest.NewRequest(c.method, "https://mail.example.com/api/v1/domains", nil)
			r.Header.Del("Origin")
			if c.host != "" {
				r.Host = c.host
			}
			if c.cookie {
				r = withCookie(r)
			}
			if c.origin != "" {
				r.Header.Set("Origin", c.origin)
			}
			if c.referer != "" {
				r.Header.Set("Referer", c.referer)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, r)

			if pass != c.wantPass {
				t.Errorf("next called = %v, want %v", pass, c.wantPass)
			}
			if rec.Code != c.wantStatus {
				t.Errorf("status = %d, want %d", rec.Code, c.wantStatus)
			}
		})
	}
}
