package orchestrator

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/Veltara-Works/vectis/internal/version"
)

// LatestRelease is the answer to "is there a newer Vectis release?", for the
// update notifier. It is read-only: unlike Plan it computes no container
// changes, stores no plan, and never touches the stack.
type LatestRelease struct {
	// Current is the version this stack runs (the orchestrator's own build,
	// which moves in lockstep with every vectis-* image).
	Current string `json:"current"`
	// Latest is the newest release the configured channel names, after the
	// manifest's Ed25519 signature, channel binding and tag checks.
	Latest string `json:"latest"`
	// Channel is the manifest's declared channel ("stable" or "rc").
	Channel string `json:"channel,omitempty"`
	// ReleasedAt is when the release workflow published Latest.
	ReleasedAt time.Time `json:"released_at"`
	// UpdateAvailable is true when Latest is newer than Current.
	UpdateAvailable bool `json:"update_available"`
	// CheckedAt is when this answer was fetched.
	CheckedAt time.Time `json:"checked_at"`
}

// LatestRelease fetches the configured release channel and reports whether it
// names a newer release than the running one. It goes through the same
// fetchReleaseManifest path as Plan, so the answer is only ever taken from a
// manifest that passed the signature and channel-binding checks: a forged or
// wrong-channel manifest is an error, never a bogus "update available".
//
// Unlike Plan it skips the anti-rollback floor. That floor stops a replayed
// older manifest from driving a downgrade PULL; this check pulls nothing. A
// server running an rc ahead of stable (a canary) legitimately sees an older
// stable manifest, which simply means "no newer release", not a failed check.
// The worst a replayed older manifest can do here is suppress a notice, which
// an attacker on the path could do anyway by blocking the request.
//
// The request is a plain GET of the public manifest and its signature: it
// carries no install identifier, licence key or usage data.
func (o *Orchestrator) LatestRelease(ctx context.Context) (*LatestRelease, error) {
	if o.cfg.ReleaseChannelURL == "" {
		return nil, fmt.Errorf("no release channel configured")
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	m, err := fetchReleaseManifest(fetchCtx, &http.Client{}, o.cfg.ReleaseChannelURL, "")
	if err != nil {
		return nil, err
	}
	return latestFromManifest(m, version.Version, time.Now().UTC())
}

// latestFromManifest builds the answer from an already-verified manifest. Pure,
// so the comparison rules are unit-testable without a network or signature.
func latestFromManifest(m *ReleaseManifest, current string, now time.Time) (*LatestRelease, error) {
	lr := &LatestRelease{
		Current:    current,
		Latest:     m.Latest,
		Channel:    m.Channel,
		ReleasedAt: m.ReleasedAt,
		CheckedAt:  now,
	}
	// A dev build (no valid release tag) can't be compared; report the latest
	// release without claiming an update is available.
	if !validReleaseTag(current) {
		return lr, nil
	}
	cmp, err := CompareReleaseTags(m.Latest, current)
	if err != nil {
		return nil, fmt.Errorf("compare release tags: %w", err)
	}
	lr.UpdateAvailable = cmp > 0
	return lr, nil
}
