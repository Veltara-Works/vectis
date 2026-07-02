package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Veltara-Works/vectis/internal/releasesign"
)

// Release-channel identifiers as published in a manifest's `channel` field and
// as bound to the well-known manifest filenames (see ExpectedChannelForURL).
const (
	ChannelStable = "stable"
	ChannelRC     = "rc"
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
	Latest     string    `json:"latest"`            // e.g. "v0.1.0-rc24"
	ReleasedAt time.Time `json:"released_at"`       // when the release workflow published the manifest
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
var releaseTagRe = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)(?:-rc(\d+))?$`)

// validReleaseTag reports whether tag is a well-formed lockstep release tag.
// Deliberately package-private; ValidReleaseTag is the exported alias reused by
// other packages (e.g. internal/cli) so this regex stays the single source of
// truth for the manifest→tag trust boundary.
func validReleaseTag(tag string) bool {
	return releaseTagRe.MatchString(tag)
}

// ValidReleaseTag is the exported form of validReleaseTag: a bare vX.Y.Z or
// vX.Y.Z-rcN and nothing else (no digest/path/whitespace/`latest`). Callers
// outside this package (the host self-update path) MUST allowlist a manifest's
// `latest` through this before using it to choose which artifact to install.
func ValidReleaseTag(tag string) bool { return validReleaseTag(tag) }

// CompareReleaseTags orders two release tags: -1 if a<b, 0 if equal, +1 if a>b.
// It errors when either side is not a valid release tag. Precedence: numeric
// major.minor.patch, then a final release outranks any of its -rc pre-releases
// (v0.1.39 > v0.1.39-rc9 > v0.1.39-rc1), with rc numbers compared numerically.
// This is the anti-rollback comparator: a signed-but-older manifest is rejected
// by comparing its `latest` against the running version (audit U-2).
func CompareReleaseTags(a, b string) (int, error) {
	pa, ok := parseReleaseTag(a)
	if !ok {
		return 0, fmt.Errorf("not a valid release tag: %q", a)
	}
	pb, ok := parseReleaseTag(b)
	if !ok {
		return 0, fmt.Errorf("not a valid release tag: %q", b)
	}
	for _, d := range []int{pa.major - pb.major, pa.minor - pb.minor, pa.patch - pb.patch} {
		if d != 0 {
			return sign(d), nil
		}
	}
	// Same X.Y.Z: a final release (not rc) sorts above any rc of that version.
	switch {
	case !pa.isRC && !pb.isRC:
		return 0, nil
	case !pa.isRC: // a is final, b is rc
		return 1, nil
	case !pb.isRC: // a is rc, b is final
		return -1, nil
	default:
		return sign(pa.rc - pb.rc), nil
	}
}

type parsedReleaseTag struct {
	major, minor, patch int
	isRC                bool
	rc                  int
}

func parseReleaseTag(tag string) (parsedReleaseTag, bool) {
	m := releaseTagRe.FindStringSubmatch(tag)
	if m == nil {
		return parsedReleaseTag{}, false
	}
	// Groups are all \d+ that already matched, so Atoi cannot fail.
	major, _ := strconv.Atoi(m[1])
	minor, _ := strconv.Atoi(m[2])
	patch, _ := strconv.Atoi(m[3])
	p := parsedReleaseTag{major: major, minor: minor, patch: patch}
	if m[4] != "" {
		p.isRC = true
		p.rc, _ = strconv.Atoi(m[4])
	}
	return p, true
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// ExpectedChannelForURL derives the release channel a manifest URL is expected
// to serve, from its well-known filename: releases-rc.json → "rc";
// releases-stable.json or the legacy releases.json alias → "stable". Any other
// path (a custom/self-hosted mirror) returns "" — channel binding is then
// skipped, leaving the signature, tag-allowlist and anti-rollback checks intact.
// Binding the fetched filename to the manifest's declared `channel` closes the
// attack where genuine, validly-signed rc manifest bytes are served at the
// stable URL to push a stable install onto pre-release images (audit U-1).
func ExpectedChannelForURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	switch path.Base(u.Path) {
	case "releases-rc.json":
		return ChannelRC
	case "releases-stable.json", "releases.json":
		return ChannelStable
	default:
		return ""
	}
}

// fetchReleaseManifest does an HTTP GET against manifestURL, decodes a
// ReleaseManifest, and returns it. All failure modes — network, non-200, bad
// JSON, missing `latest`, signature, channel-mismatch, rollback — return an
// error so the caller can decide whether to surface it as a hard plan failure or
// a soft warning. Callers should pass a ctx with a sensible timeout; this
// function adds none of its own.
//
// versionFloor is the running stack version (version.Version). When it is a
// valid release tag, a manifest whose `latest` is OLDER than it is rejected as a
// signed-rollback attempt (audit U-2); pass "" (or a dev/non-tag value) to skip
// that check. Channel binding (audit U-1) is derived from manifestURL and needs
// no caller input.
func fetchReleaseManifest(ctx context.Context, httpClient *http.Client, manifestURL, versionFloor string) (*ReleaseManifest, error) {
	body, err := httpGetBytes(ctx, httpClient, manifestURL, "application/json", 64*1024)
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
	sig, err := httpGetBytes(ctx, httpClient, manifestURL+".ed25519", "", 4*1024)
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
	// Channel binding (audit U-1): the signature proves "some release key signed
	// these bytes", not "these bytes belong at this URL". One key signs every
	// channel's manifest, so genuine, validly-signed releases-rc.json bytes served
	// at the stable URL would otherwise push a stable install onto rc images. Bind
	// the well-known filename to the manifest's declared channel and reject a
	// mismatch (or a missing channel at a known-channel URL).
	if expected := ExpectedChannelForURL(manifestURL); expected != "" {
		if m.Channel == "" {
			return nil, fmt.Errorf("release manifest at %s declares no channel (want %q)", manifestURL, expected)
		}
		if m.Channel != expected {
			return nil, fmt.Errorf("release manifest channel mismatch: URL %s expects %q but manifest declares %q", manifestURL, expected, m.Channel)
		}
	}
	// Anti-rollback (audit U-2): a manifest is public, so a MITM/replay can serve
	// a genuine OLDER signed manifest to force the whole stack downgrade to older,
	// possibly-vulnerable images. Refuse anything older than the running version.
	// Skipped when versionFloor isn't a valid release tag (dev builds), and an
	// equal version is fine (a no-op plan). An intentional downgrade stays a
	// deliberate, pinned manual operation — never an automatic manifest-driven one.
	if validReleaseTag(versionFloor) {
		cmp, err := CompareReleaseTags(m.Latest, versionFloor)
		if err != nil {
			return nil, fmt.Errorf("compare release tags: %w", err)
		}
		if cmp < 0 {
			return nil, fmt.Errorf("release manifest `latest` = %q is older than the running version %q (refusing signed rollback)", m.Latest, versionFloor)
		}
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
