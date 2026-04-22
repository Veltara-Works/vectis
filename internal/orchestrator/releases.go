package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
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

// fetchReleaseManifest does an HTTP GET against url, decodes a ReleaseManifest,
// and returns it. All failure modes — network, non-200, bad JSON, missing
// `latest` — return an error so the caller can decide whether to surface it
// as a hard plan failure or a soft warning. Callers should pass a ctx with a
// sensible timeout; this function adds none of its own.
func fetchReleaseManifest(ctx context.Context, httpClient *http.Client, url string) (*ReleaseManifest, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build release manifest request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch release manifest: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		// Read at most 512 bytes so a miswired proxy returning HTML can't balloon logs.
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("release manifest HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var m ReleaseManifest
	if err := json.NewDecoder(resp.Body).Decode(&m); err != nil {
		return nil, fmt.Errorf("decode release manifest: %w", err)
	}
	if m.Latest == "" {
		return nil, fmt.Errorf("release manifest missing `latest` field")
	}
	return &m, nil
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
