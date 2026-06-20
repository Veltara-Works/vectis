package license

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// embeddedJWKS is the build-time fallback keyset, compiled into the binary so
// an air-gapped install can verify with no network and no prior cache. It
// holds ValidonX's current production signing key (kid validonx-2026-05).
// Refresh this file when ValidonX rotates and rebuild.
//
//go:embed embedded_jwks.json
var embeddedJWKS []byte

// maxJWKSBytes caps a fetched/loaded JWKS document to defend against a
// hostile or broken endpoint streaming an unbounded body.
const maxJWKSBytes = 256 * 1024

// defaultFetchTimeout bounds a single live JWKS fetch.
const defaultFetchTimeout = 10 * time.Second

// Source identifies which layer satisfied a JWKS resolution, for diagnostics.
type Source string

const (
	SourceLive     Source = "live"     // fetched fresh over HTTPS
	SourceCache    Source = "cache"    // read from the on-disk cache
	SourceEmbedded Source = "embedded" // build-time fallback key
)

// Resolver resolves the trusted JWKS through three layers, first success wins
// (contract §7): live HTTPS -> on-disk cache -> embedded fallback. A
// successful live fetch is written through to the cache. Verification never
// needs the network on the hot path: callers resolve once (and refresh in the
// background) into an in-memory [Provider], then Verify against that KeySet.
type Resolver struct {
	// LiveURL is the JWKS endpoint. Must be https:// (http is refused). Empty
	// disables the live layer (cache/embedded only).
	LiveURL string
	// CachePath is where a successful live fetch is persisted and the cache
	// layer reads from. Empty disables the cache layer.
	CachePath string
	// Embedded is the build-time fallback JWKS bytes. Defaults to the
	// compiled-in keyset; overridable for tests.
	Embedded []byte
	// HTTPClient performs the live fetch. Defaults to a timeout-bounded client.
	HTTPClient *http.Client
}

// NewResolver builds a Resolver with production defaults: the embedded keyset
// and a timeout-bounded HTTP client.
func NewResolver(liveURL, cachePath string) *Resolver {
	return &Resolver{
		LiveURL:    liveURL,
		CachePath:  cachePath,
		Embedded:   embeddedJWKS,
		HTTPClient: &http.Client{Timeout: defaultFetchTimeout},
	}
}

// Resolve returns the trusted KeySet and the layer that produced it. It tries
// live, then cache, then embedded; the first layer that yields a parseable,
// non-empty Ed25519 keyset wins. A live success is written through to the
// cache (best-effort; a cache-write failure does not fail resolution). An
// error is returned only if every layer fails.
func (r *Resolver) Resolve(ctx context.Context) (*KeySet, Source, error) {
	var errs []string

	// 1. Live (HTTPS only).
	if r.LiveURL != "" {
		raw, err := r.fetchLive(ctx)
		if err != nil {
			errs = append(errs, "live: "+err.Error())
		} else if ks, perr := ParseJWKS(raw); perr != nil {
			errs = append(errs, "live: "+perr.Error())
		} else {
			r.writeCache(raw) // best-effort write-through
			return ks, SourceLive, nil
		}
	}

	// 2. On-disk cache (size-bounded read, so an oversized cache file or
	// symlink can't defeat maxJWKSBytes).
	if r.CachePath != "" {
		if raw, err := readFileCapped(r.CachePath); err != nil {
			errs = append(errs, "cache: "+err.Error())
		} else if ks, perr := ParseJWKS(raw); perr != nil {
			errs = append(errs, "cache: "+perr.Error())
		} else {
			return ks, SourceCache, nil
		}
	}

	// 3. Embedded fallback (capped too: Embedded is an exported field).
	if len(r.Embedded) == 0 {
		errs = append(errs, "embedded: no keys compiled in")
	} else if len(r.Embedded) > maxJWKSBytes {
		errs = append(errs, fmt.Sprintf("embedded: exceeds %d bytes", maxJWKSBytes))
	} else if ks, err := ParseJWKS(r.Embedded); err != nil {
		errs = append(errs, "embedded: "+err.Error())
	} else {
		return ks, SourceEmbedded, nil
	}

	return nil, "", fmt.Errorf("jwks resolution failed (%s)", strings.Join(errs, "; "))
}

// fetchLive fetches and returns the raw JWKS bytes over HTTPS. A non-HTTPS
// URL is refused outright (contract §7) rather than fetched insecurely.
func (r *Resolver) fetchLive(ctx context.Context) ([]byte, error) {
	if !strings.HasPrefix(strings.ToLower(r.LiveURL), "https://") {
		return nil, fmt.Errorf("live jwks url must be https, got %q", r.LiveURL)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, r.LiveURL, nil)
	if err != nil {
		return nil, err
	}
	client := r.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultFetchTimeout}
	}
	// Enforce HTTPS across redirects too: a hostile or misconfigured endpoint
	// could 30x to http:// and slip the JWKS fetch onto cleartext despite the
	// initial scheme check. Copy the client so we don't mutate the caller's,
	// and refuse any redirect to a non-HTTPS target.
	c := *client
	c.CheckRedirect = func(req *http.Request, _ []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("refusing redirect to non-https url %q", req.URL.String())
		}
		return nil
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxJWKSBytes {
		return nil, fmt.Errorf("jwks body exceeds %d bytes", maxJWKSBytes)
	}
	return raw, nil
}

// readFileCapped reads at most maxJWKSBytes from path, failing if the file
// exceeds the cap rather than loading it wholesale into memory.
func readFileCapped(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxJWKSBytes {
		return nil, fmt.Errorf("cache jwks exceeds %d bytes", maxJWKSBytes)
	}
	return raw, nil
}

// writeCache persists raw JWKS bytes to CachePath atomically (temp file +
// rename). Best-effort: errors are returned for the caller to log but never
// fail a resolution that already succeeded over the wire.
func (r *Resolver) writeCache(raw []byte) error {
	if r.CachePath == "" {
		return nil
	}
	dir := filepath.Dir(r.CachePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".jwks-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once renamed
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, r.CachePath)
}
