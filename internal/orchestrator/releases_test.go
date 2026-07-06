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
	// The helper serves at /releases.json → the stable channel is expected, so a
	// stable-channel manifest passes channel binding. A newer `latest` than the
	// floor passes the anti-rollback check.
	url, cleanup := signedManifestServer(t, `{"latest":"v0.1.39","released_at":"2026-04-22T08:00:00Z","channel":"stable"}`, true)
	defer cleanup()

	m, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "v0.1.38")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if m.Latest != "v0.1.39" {
		t.Errorf("Latest: want v0.1.39, got %q", m.Latest)
	}
	if m.Channel != "stable" {
		t.Errorf("Channel: want stable, got %q", m.Channel)
	}
	if m.ReleasedAt.IsZero() {
		t.Error("ReleasedAt should be populated")
	}
}

// A genuine, validly-signed rc-channel manifest served at the stable URL must be
// rejected by channel binding (audit U-1) even though its signature is valid.
func TestFetchReleaseManifest_ChannelMismatch(t *testing.T) {
	url, cleanup := signedManifestServer(t, `{"latest":"v0.1.39-rc1","channel":"rc"}`, true)
	defer cleanup()

	_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "")
	if err == nil {
		t.Fatal("expected channel-mismatch rejection")
	}
	if !strings.Contains(err.Error(), "channel") {
		t.Errorf("error should mention channel, got: %v", err)
	}
}

// A signed manifest at a known-channel URL that declares no channel at all is
// unbound and must be rejected (audit U-1).
func TestFetchReleaseManifest_MissingChannel(t *testing.T) {
	url, cleanup := signedManifestServer(t, `{"latest":"v0.1.39"}`, true)
	defer cleanup()

	_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "")
	if err == nil {
		t.Fatal("expected rejection of channel-less manifest at a known-channel URL")
	}
	if !strings.Contains(err.Error(), "channel") {
		t.Errorf("error should mention channel, got: %v", err)
	}
}

// A genuine, validly-signed OLDER manifest replayed at the stable URL must be
// rejected as a signed rollback when the running version is newer (audit U-2).
func TestFetchReleaseManifest_RollbackRejected(t *testing.T) {
	url, cleanup := signedManifestServer(t, `{"latest":"v0.1.30","channel":"stable"}`, true)
	defer cleanup()

	_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "v0.1.38")
	if err == nil {
		t.Fatal("expected signed-rollback rejection")
	}
	if !strings.Contains(err.Error(), "older") {
		t.Errorf("error should mention rollback/older, got: %v", err)
	}
}

// Same-version manifest (a no-op plan) is allowed past the anti-rollback gate.
func TestFetchReleaseManifest_SameVersionAllowed(t *testing.T) {
	url, cleanup := signedManifestServer(t, `{"latest":"v0.1.38","channel":"stable"}`, true)
	defer cleanup()

	if _, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "v0.1.38"); err != nil {
		t.Fatalf("same-version manifest should be allowed, got: %v", err)
	}
}

// A manifest with no signature published (404 on .ed25519) must be rejected —
// the caller then soft-fails to local-only planning.
func TestFetchReleaseManifest_MissingSignature(t *testing.T) {
	url, cleanup := signedManifestServer(t, `{"latest":"v0.1.0-rc24"}`, false)
	defer cleanup()

	_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "")
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

	_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, srv.URL+"/releases.json", "")
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

	_, err := fetchReleaseManifest(context.Background(), srv.Client(), srv.URL+"/releases.json", "")
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

	_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "")
	if err == nil {
		t.Fatal("expected decode error, got nil")
	}
}

func TestFetchReleaseManifest_MissingLatest(t *testing.T) {
	url, cleanup := signedManifestServer(t, `{"channel":"rc"}`, true)
	defer cleanup()

	_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "")
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
		_, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "")
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

	_, err := fetchReleaseManifest(ctx, srv.Client(), srv.URL+"/releases.json", "")
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

func TestCompareReleaseTags(t *testing.T) {
	less := [][2]string{
		{"v0.1.38", "v0.1.39"},
		{"v0.1.9", "v0.1.10"},
		{"v0.1.39-rc1", "v0.1.39"},      // rc precedes its final release
		{"v0.1.39-rc1", "v0.1.39-rc2"},  // rc numeric, not lexical
		{"v0.1.39-rc9", "v0.1.39-rc10"}, // rc numeric, not lexical
		{"v0.9.9", "v1.0.0"},
	}
	for _, c := range less {
		got, err := CompareReleaseTags(c[0], c[1])
		if err != nil {
			t.Fatalf("CompareReleaseTags(%q,%q): %v", c[0], c[1], err)
		}
		if got != -1 {
			t.Errorf("CompareReleaseTags(%q,%q) = %d, want -1", c[0], c[1], got)
		}
		// Antisymmetry.
		if rev, _ := CompareReleaseTags(c[1], c[0]); rev != 1 {
			t.Errorf("CompareReleaseTags(%q,%q) = %d, want 1", c[1], c[0], rev)
		}
	}
	for _, eq := range []string{"v0.1.39", "v0.1.39-rc3"} {
		if got, err := CompareReleaseTags(eq, eq); err != nil || got != 0 {
			t.Errorf("CompareReleaseTags(%q,%q) = %d, %v; want 0, nil", eq, eq, got, err)
		}
	}
	if _, err := CompareReleaseTags("v0.1.39", "latest"); err == nil {
		t.Error("expected error comparing against an invalid tag")
	}
}

func TestExpectedChannelForURL(t *testing.T) {
	cases := map[string]string{
		"https://dl.vectismail.com/releases.json":         ChannelStable,
		"https://dl.vectismail.com/releases-stable.json":  ChannelStable,
		"https://dl.vectismail.com/releases-rc.json":      ChannelRC,
		"https://dl.vectismail.com/releases-rc.json?x=1":  ChannelRC,
		"https://mirror.example.com/custom/manifest.json": "",
		"://bad url": "",
	}
	for in, want := range cases {
		if got := ExpectedChannelForURL(in); got != want {
			t.Errorf("ExpectedChannelForURL(%q) = %q, want %q", in, got, want)
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

// A manifest carrying a valid images map parses and exposes the per-service
// digests (REL-3 part 2).
func TestFetchReleaseManifest_ImagesParsed(t *testing.T) {
	dig := "sha256:8bd19c3a278a2cb0602b362d9fd69566c332e053a6c805119ba0cf684601db90"
	body := `{"latest":"v0.1.42","released_at":"2026-07-06T08:00:00Z","channel":"stable","images":{"api":"` + dig + `"}}`
	url, cleanup := signedManifestServer(t, body, true)
	defer cleanup()

	m, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "v0.1.41")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := m.Images["api"]; got != dig {
		t.Errorf("Images[api]: want %q, got %q", dig, got)
	}
}

// A manifest with a malformed image digest is rejected even when validly signed:
// the digest is spliced into a compose image ref, so it must be a bare sha256.
func TestFetchReleaseManifest_BadImageDigestRejected(t *testing.T) {
	for _, bad := range []string{
		`"sha256:zzzz"`, // not hex / wrong length
		`"v0.1.42"`,     // a tag, not a digest
		`"sha512:` + strings.Repeat("a", 64) + `"`,           // wrong algorithm
		`"ghcr.io/x@sha256:` + strings.Repeat("a", 64) + `"`, // path-carrying
	} {
		body := `{"latest":"v0.1.42","released_at":"2026-07-06T08:00:00Z","channel":"stable","images":{"api":` + bad + `}}`
		url, cleanup := signedManifestServer(t, body, true)
		m, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "v0.1.41")
		cleanup()
		if err == nil {
			t.Errorf("digest %s: expected rejection, got manifest %+v", bad, m)
		}
	}
}

// A manifest with no images map is valid — the caller degrades to a tag-only pin.
func TestFetchReleaseManifest_NoImagesIsValid(t *testing.T) {
	url, cleanup := signedManifestServer(t, `{"latest":"v0.1.42","released_at":"2026-07-06T08:00:00Z","channel":"stable"}`, true)
	defer cleanup()

	m, err := fetchReleaseManifest(context.Background(), http.DefaultClient, url, "v0.1.41")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(m.Images) != 0 {
		t.Errorf("expected no images, got %v", m.Images)
	}
}

func TestRewriteReleaseImageRef(t *testing.T) {
	const dig = "sha256:8bd19c3a278a2cb0602b362d9fd69566c332e053a6c805119ba0cf684601db90"
	cases := []struct {
		name          string
		image, tag, d string
		want          string
	}{
		{"tag+digest pins", "ghcr.io/veltara-works/vectis-api:v0.1.41", "v0.1.42", dig,
			"ghcr.io/veltara-works/vectis-api:v0.1.42@" + dig},
		{"no digest = tag only (graceful)", "ghcr.io/veltara-works/vectis-api:v0.1.41", "v0.1.42", "",
			"ghcr.io/veltara-works/vectis-api:v0.1.42"},
		{"replaces an existing digest", "ghcr.io/veltara-works/vectis-api:v0.1.41@sha256:" + strings.Repeat("0", 64), "v0.1.42", dig,
			"ghcr.io/veltara-works/vectis-api:v0.1.42@" + dig},
		{"cert-extractor (hyphenated svc)", "ghcr.io/veltara-works/vectis-cert-extractor:v0.1.41", "v0.1.42", dig,
			"ghcr.io/veltara-works/vectis-cert-extractor:v0.1.42@" + dig},
		{"non-vectis untouched", "postgres:17-alpine", "v0.1.42", dig, "postgres:17-alpine"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := rewriteReleaseImageRef(tc.image, tc.tag, tc.d); got != tc.want {
				t.Errorf("want %q, got %q", tc.want, got)
			}
		})
	}
}

func TestVectisServiceFromImage(t *testing.T) {
	cases := []struct {
		image   string
		wantSvc string
		wantOK  bool
	}{
		{"ghcr.io/veltara-works/vectis-api:v0.1.42", "api", true},
		{"ghcr.io/veltara-works/vectis-cert-extractor:v0.1.42@sha256:" + strings.Repeat("a", 64), "cert-extractor", true},
		{"ghcr.io/veltara-works/vectis-orchestrator", "orchestrator", true},
		{"postgres:17-alpine", "", false},
	}
	for _, tc := range cases {
		svc, ok := vectisServiceFromImage(tc.image)
		if svc != tc.wantSvc || ok != tc.wantOK {
			t.Errorf("%s: want (%q,%v), got (%q,%v)", tc.image, tc.wantSvc, tc.wantOK, svc, ok)
		}
	}
}
