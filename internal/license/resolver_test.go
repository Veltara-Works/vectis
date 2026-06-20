package license

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// validJWKS is a parseable Ed25519 keyset (the sandbox key) used as the live
// and cache payload in resolver tests.
const validJWKS = `{"keys":[{"kty":"OKP","crv":"Ed25519","x":"atURRxq1FNAsX4KrElpyHLRr0JzQrmcWCOYHb-cNPmw","kid":"validonx-sandbox-2026-06","use":"sig","alg":"EdDSA"}]}`

func TestResolveEmbeddedFallback(t *testing.T) {
	// No live URL, no cache -> embedded keyset (the compiled-in prod key).
	r := NewResolver("", "")
	ks, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src != SourceEmbedded {
		t.Fatalf("source: got %q, want embedded", src)
	}
	if _, ok := ks.lookup("validonx-2026-05"); !ok {
		t.Fatalf("embedded keyset missing production kid validonx-2026-05")
	}
}

func TestResolveLiveWritesThroughToCache(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(validJWKS))
	}))
	defer srv.Close()

	cachePath := filepath.Join(t.TempDir(), "sub", "jwks.json")
	r := NewResolver(srv.URL, cachePath)
	r.HTTPClient = srv.Client() // trust the test TLS cert

	ks, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src != SourceLive {
		t.Fatalf("source: got %q, want live", src)
	}
	if _, ok := ks.lookup("validonx-sandbox-2026-06"); !ok {
		t.Fatalf("live keyset missing expected kid")
	}
	// Cache must have been written through and be parseable.
	raw, err := os.ReadFile(cachePath)
	if err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	if _, err := ParseJWKS(raw); err != nil {
		t.Fatalf("cached bytes not a valid jwks: %v", err)
	}
}

func TestResolveFallsToCacheWhenLiveFails(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	cachePath := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(cachePath, []byte(validJWKS), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewResolver(srv.URL, cachePath)
	r.HTTPClient = srv.Client()

	_, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src != SourceCache {
		t.Fatalf("source: got %q, want cache", src)
	}
}

func TestResolveRefusesNonHTTPS(t *testing.T) {
	// An http:// live URL must be refused (not fetched) and fall through to
	// embedded, never silently fetched over cleartext.
	r := NewResolver("http://api.validonx.com/.well-known/jwks.json", "")
	_, src, err := r.Resolve(context.Background())
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if src != SourceEmbedded {
		t.Fatalf("source: got %q, want embedded (http live refused)", src)
	}
	// And fetchLive itself reports the reason.
	if _, ferr := r.fetchLive(context.Background()); ferr == nil {
		t.Fatalf("fetchLive accepted an http:// url")
	}
}

func TestResolveAllLayersFail(t *testing.T) {
	r := &Resolver{LiveURL: "", CachePath: "", Embedded: nil}
	if _, _, err := r.Resolve(context.Background()); err == nil {
		t.Fatalf("expected error when every layer is empty")
	}
}

func TestProviderRefreshAndRetainOnFailure(t *testing.T) {
	p := NewProvider(NewResolver("", "")) // embedded-only, always succeeds
	if p.Current() != nil {
		t.Fatalf("Current should be nil before first Refresh")
	}
	src, err := p.Refresh(context.Background())
	if err != nil || src != SourceEmbedded {
		t.Fatalf("refresh: src=%q err=%v", src, err)
	}
	if p.Current() == nil {
		t.Fatalf("Current should be populated after Refresh")
	}
	if p.Source() != SourceEmbedded {
		t.Fatalf("Source: got %q, want embedded", p.Source())
	}

	// A subsequent failing refresh must retain the previously-loaded keyset.
	prev := p.Current()
	p.resolver = &Resolver{Embedded: nil} // all layers empty -> fails
	if _, err := p.Refresh(context.Background()); err == nil {
		t.Fatalf("expected refresh error")
	}
	if p.Current() != prev {
		t.Fatalf("Current should be retained on failed refresh")
	}
}
