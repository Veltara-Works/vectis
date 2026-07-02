package orchestrator

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/releasesign"
)

// signedManifestServer serves a manifest body at /releases.json and (when
// signIt) a matching Ed25519 signature at /releases.json.ed25519, and injects
// the ephemeral public key as the embedded release key for the test. Returns the
// manifest URL and a cleanup func.
func signedManifestServer(t *testing.T, body string, signIt bool) (string, func()) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	restore := releasesign.SetSigningKeyForTest(pub)

	var sig string
	if signIt {
		sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(body)))
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".ed25519") {
			if sig == "" {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			_, _ = w.Write([]byte(sig))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	return srv.URL + "/releases.json", func() { srv.Close(); restore() }
}

func TestFetchReleaseManifest_Success(t *testing.T) {
	url, cleanup := signedManifestServer(t, `{"latest":"v0.1.0-rc24","released_at":"2026-04-22T08:00:00Z","channel":"rc"}`, true)
	defer cleanup()

	m, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Latest != "v0.1.0-rc24" {
		t.Errorf("Latest: want v0.1.0-rc24, got %q", m.Latest)
	}
	if m.Channel != "rc" {
		t.Errorf("Channel: want rc, got %q", m.Channel)
	}
	if m.ReleasedAt.IsZero() {
		t.Error("ReleasedAt should be populated")
	}
}

// A manifest with no signature published (404 on .ed25519) must be rejected —
// the caller then soft-fails to local-only planning.
func TestFetchReleaseManifest_MissingSignature(t *testing.T) {
	url, cleanup := signedManifestServer(t, `{"latest":"v0.1.0-rc24"}`, false)
	defer cleanup()

	_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url)
	if err == nil {
		t.Fatal("expected error when signature is absent")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error should mention signature, got: %v", err)
	}
}

// A manifest whose bytes were tampered after signing must fail verification.
func TestFetchReleaseManifest_TamperedBody(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	restore := releasesign.SetSigningKeyForTest(pub)
	defer restore()

	original := `{"latest":"v0.1.0-rc24"}`
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(original)))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, ".ed25519") {
			_, _ = w.Write([]byte(sig))
			return
		}
		// Serve a DIFFERENT (attacker-swapped) tag under the honest signature.
		_, _ = w.Write([]byte(`{"latest":"v9.9.9"}`))
	}))
	defer srv.Close()

	_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, srv.URL+"/releases.json")
	if err == nil {
		t.Fatal("expected signature failure on tampered manifest body")
	}
	if !strings.Contains(err.Error(), "signature") {
		t.Errorf("error should mention signature, got: %v", err)
	}
}

func TestFetchReleaseManifest_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	_, err := fetchReleaseManifest(context.Background(), srv.Client(), srv.URL+"/releases.json")
	if err == nil {
		t.Fatal("expected error on 404, got nil")
	}
	if !strings.Contains(err.Error(), "404") {
		t.Errorf("error should mention 404, got: %v", err)
	}
}

func TestFetchReleaseManifest_BadJSON(t *testing.T) {
	url, cleanup := signedManifestServer(t, "not valid json at all", true)
	defer cleanup()

	_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url)
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}

func TestFetchReleaseManifest_MissingLatest(t *testing.T) {
	url, cleanup := signedManifestServer(t, `{"channel":"rc"}`, true)
	defer cleanup()

	_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url)
	if err == nil {
		t.Fatal("expected error for missing latest field")
	}
	if !strings.Contains(err.Error(), "latest") {
		t.Errorf("error should mention `latest`, got: %v", err)
	}
}

// A signed manifest whose `latest` is a floating/malformed tag must be rejected
// by the allowlist even though the signature is valid (E-H2 defence in depth).
func TestFetchReleaseManifest_BadTagRejected(t *testing.T) {
	for _, bad := range []string{`{"latest":"latest"}`, `{"latest":"v1.2.3@sha256:deadbeef"}`, `{"latest":"evil/img:tag"}`} {
		url, cleanup := signedManifestServer(t, bad, true)
		_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url)
		cleanup()
		if err == nil {
			t.Errorf("expected rejection of %q", bad)
		}
	}
}

func TestFetchReleaseManifest_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"latest":"v0.1.0-rc24"}`))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	_, err := fetchReleaseManifest(ctx, srv.Client(), srv.URL+"/releases.json")
	if err == nil {
		t.Fatal("expected timeout error, got nil")
	}
}

func TestValidReleaseTag(t *testing.T) {
	good := []string{"v0.1.0", "v0.1.39", "v1.2.3", "v0.1.0-rc24", "v10.20.30-rc1"}
	bad := []string{"latest", "", "0.1.0", "v0.1", "v0.1.0-rc", "v0.1.0@sha256:x", "v0.1.0 v9",
		"ghcr.io/x:v0.1.0", "v0.1.0-beta1", "v0.1.0-rc24 "}
	for _, g := range good {
		if !validReleaseTag(g) {
			t.Errorf("valid tag %q rejected", g)
		}
	}
	for _, b := range bad {
		if validReleaseTag(b) {
			t.Errorf("invalid tag %q accepted", b)
		}
	}
}

func TestRewriteReleaseTag(t *testing.T) {
	cases := []struct {
		name  string
		image string
		tag   string
		want  string
	}{
		{
			name:  "vectis-api gets retagged",
			image: "ghcr.io/veltara-works/vectis-api:v0.1.0-rc21",
			tag:   "v0.1.0-rc24",
			want:  "ghcr.io/veltara-works/vectis-api:v0.1.0-rc24",
		},
		{
			name:  "vectis-dovecot gets retagged",
			image: "ghcr.io/veltara-works/vectis-dovecot:v0.1.0-rc21",
			tag:   "v0.1.0-rc24",
			want:  "ghcr.io/veltara-works/vectis-dovecot:v0.1.0-rc24",
		},
		{
			name:  "postgres upstream image untouched",
			image: "postgres:17-alpine",
			tag:   "v0.1.0-rc24",
			want:  "postgres:17-alpine",
		},
		{
			name:  "traefik upstream image untouched",
			image: "traefik:v3.3",
			tag:   "v0.1.0-rc24",
			want:  "traefik:v3.3",
		},
		{
			name:  "acme.sh upstream image untouched",
			image: "neilpang/acme.sh:latest",
			tag:   "v0.1.0-rc24",
			want:  "neilpang/acme.sh:latest",
		},
		{
			name:  "vectis image without tag left alone",
			image: "ghcr.io/veltara-works/vectis-api",
			tag:   "v0.1.0-rc24",
			want:  "ghcr.io/veltara-works/vectis-api",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := rewriteReleaseTag(tc.image, tc.tag)
			if got != tc.want {
				t.Errorf("\n  image: %s\n  tag:   %s\n  want:  %s\n  got:   %s", tc.image, tc.tag, tc.want, got)
			}
		})
	}
}
