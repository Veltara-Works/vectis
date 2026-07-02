package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/releasesign"
)

// DefaultReleaseChannelURL is the well-known location of the Vectis release
// manifest on Cloudflare R2 (served via dl.vectismail.com). Published by the
// GitHub Release workflow after all container images + binary are live.
const DefaultReleaseChannelURL = "https://dl.vectismail.com/releases.json"

// ReleaseManifest describes the latest published release of Vectis. The
// server-side schema is deliberately minimal: `latest` is the canonical
// lockstep tag applied to every vectis-* container image. `channel` lets
// future manifests distinguish stable from rc without changing the URL.
type ReleaseManifest struct {
	Latest     string    `json:"latest"`           // e.g. "v0.1.0-rc24"
	ReleasedAt time.Time `json:"released_at"`      // when the release workflow published the manifest
	Channel    string    `json:"channel,omitempty"` // "rc" or "stable"; optional
}

// releaseServicePrefix identifies which compose services track the release
// channel. Lockstep: all five images share a single tag per release.
const releaseServicePrefix = "ghcr.io/veltara-works/vectis-"

// releaseTagRe is the strict allowlist for a manifest's `latest` tag: a bare
// vX.Y.Z or vX.Y.Z-rcN and nothing else. The anchored pattern rejects any value
// carrying a digest, registry path, extra tag, or whitespace — e.g. "latest",
// "v1.2.3@sha256:…", "evil/image:tag", "v1.2.3 v9" — so a compromised or MITM'd
// release manifest cannot drive the orchestrator to pull an arbitrary or
// floating image (audit E-H2). This is the manifest→tag trust boundary; it does
// not authenticate the manifest itself (that is the signature layer).
var releaseTagRe = regexp.MustCompile(`^v\d+\.\d+\.\d+(-rc\d+)?$`)

// validReleaseTag reports whether tag is a well-formed lockstep release tag.
func validReleaseTag(tag string) bool {
	return releaseTagRe.MatchString(tag)
}

// fetchReleaseManifest does an HTTP GET against url, decodes a ReleaseManifest,
// and returns it. All failure modes — network, non-200, bad JSON, missing
// `latest` — return an error so the caller can decide whether to surface it
// as a hard plan failure or a soft warning. Callers should pass a ctx with a
// sensible timeout; this function adds none of its own.
func fetchReleaseManifest(ctx context.Context, httpClient *http.Client, url string) (*ReleaseManifest, error) {
	body, err := httpGetBytes(ctx, httpClient, url, "application/json", 64*1024)
	if err != nil {
		return nil, fmt.Errorf("fetch release manifest: %w", err)
	}

	// Authenticate the manifest with the offline Ed25519 release signature BEFORE
	// trusting any field (audit E-H2). imageHasFloatingTag guards the compose
	// file, but the manifest arrives over the network and drives which image tag
	// the orchestrator plans to pull; a compromised R2/DNS or TLS-strip MITM can
	// serve a manifest but cannot forge its signature. The signature is the raw
	// 64-byte Ed25519 signature (base64) over the exact manifest bytes, published
	// alongside the manifest at <url>.ed25519.
	//
	// Any failure here returns an error, which the caller (Plan) treats as a soft
	// "release channel unavailable" warning and falls back to local compose-vs-
	// running drift — so a forged or unsigned manifest yields "no update info",
	// never a bad/downgrade pull.
	sig, err := httpGetBytes(ctx, httpClient, url+".ed25519", "", 4*1024)
	if err != nil {
		return nil, fmt.Errorf("fetch release manifest signature: %w", err)
	}
	if err := releasesign.Verify(body, string(sig)); err != nil {
		return nil, fmt.Errorf("release manifest signature: %w", err)
	}

	var m ReleaseManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("decode release manifest: %w", err)
	}
	if m.Latest == "" {
		return nil, fmt.Errorf("release manifest missing `latest` field")
	}
	// Re-validate the manifest-supplied tag before any caller uses it to rewrite
	// image references (audit E-H2): defence in depth behind the signature, and a
	// clear invariant that m.Latest is a bare vX.Y.Z[-rcN] with no digest/path.
	if !validReleaseTag(m.Latest) {
		return nil, fmt.Errorf("release manifest `latest` = %q is not a valid release tag", m.Latest)
	}
	return &m, nil
}

// httpGetBytes GETs url and returns up to maxBytes of the response body, erroring
// on a transport failure or non-200 status. accept, when non-empty, sets the
// Accept header.
func httpGetBytes(ctx context.Context, httpClient *http.Client, url, accept string, maxBytes int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

// rewriteReleaseTag returns image with its tag replaced by tag, if image is a
// vectis-* release-channel-managed image. Non-vectis images (postgres,
// valkey, traefik, acme.sh) are returned unchanged. If the image has no tag
// or cannot be parsed, it's returned unchanged — the caller will either find
// a match against running versions or treat it as orchestrator-unmanaged.
func rewriteReleaseTag(image, tag string) string {
	if !strings.HasPrefix(image, releaseServicePrefix) {
		return image
	}
	idx := strings.LastIndex(image, ":")
	if idx < len(releaseServicePrefix) {
		// No tag, or `:` is inside the registry hostname (shouldn't happen for ghcr.io).
		return image
	}
	return image[:idx] + ":" + tag
}
