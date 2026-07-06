package orchestrator

import (
	"strings"
	"time"
)

// Plan describes the diff between the current and desired system state.
// Computed by Plan() and consumed by Apply(). Becomes stale if the system
// state changes between plan and apply (Spec D.9).
type Plan struct {
	ID               string            `json:"id"`
	CreatedAt        time.Time         `json:"created_at"`
	ConfigHash       string            `json:"config_hash"`
	BaselineVersions map[string]string `json:"baseline_versions"`
	Changes          []PlanChange      `json:"changes"`
	MigrationsUp     int               `json:"migrations_up"`
	// ReleaseTag, if non-empty, is the lockstep target tag fetched from the
	// release channel during Plan. Changes[] are computed against this tag
	// (not the compose file's on-disk tags). The UI renders this so users
	// can see which release the proposed update would land them on.
	ReleaseTag string `json:"release_tag,omitempty"`
	// ImageDigests, when present, maps each vectis-* service to the immutable
	// sha256 digest the signed release manifest pins it to (REL-3). Apply pins
	// the rendered compose to these digests so the recreate runs exactly the
	// bytes the manifest names. Empty when the manifest carried no digests
	// (pre-REL-3 publisher or self-hosted mirror) — Apply then pins by tag only.
	ImageDigests map[string]string `json:"image_digests,omitempty"`
	// Warnings collects non-fatal issues that the caller should surface to
	// the user (e.g. release-channel fetch failed, falling back to local
	// compose). Not a substitute for error returns — hard failures still
	// propagate as errors per §10 blocker #2.
	Warnings []string `json:"warnings,omitempty"`
}

// PlanChange describes a single change in a plan.
type PlanChange struct {
	Service  string `json:"service"`
	Type     string `json:"type"` // "create", "update", "remove", "config", "migrate"
	OldImage string `json:"old_image,omitempty"`
	NewImage string `json:"new_image,omitempty"`
	Detail   string `json:"detail,omitempty"`
}

// IsEmpty reports whether the plan contains no changes.
func (p *Plan) IsEmpty() bool {
	return len(p.Changes) == 0 && p.MigrationsUp == 0
}

// imageHasFloatingTag reports whether a docker image reference uses the
// `:latest` tag (explicit or implicit). Plan rejects compose files that
// pin Vectis services to floating tags because:
//   - release.yml's `:latest` is published only on stable tags. An rc bump
//     followed by a release.yml fix-forward can leave `:latest` pointing at
//     an older release than the running stack, which on `docker compose pull`
//     would silently downgrade api/orchestrator and crash-loop on migration
//     mismatch (see feedback_latest_tag_unbumped.md).
//   - Apply diffs running-vs-declared images to compute Plan.Changes; with
//     a floating tag, "running == declared" is meaningless because the
//     declared tag is whatever happens to be live in ghcr at the moment.
//
// The check ignores image references with no tag (no Vectis ghcr image is
// shipped without a version tag) and any registry-host portion of the ref.
func imageHasFloatingTag(image string) bool {
	if image == "" {
		return false
	}
	// Strip everything before the last "/" so we only look at the
	// "name:tag" segment. ghcr.io/owner/repo:tag → repo:tag.
	name := image
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}
	idx := strings.LastIndex(name, ":")
	if idx < 0 {
		// No tag at all means docker defaults to :latest. Reject.
		return true
	}
	return name[idx+1:] == "latest"
}

// IsStale checks whether the plan's baseline still matches the current system
// state. Returns true if the config hash or container versions have changed
// since the plan was computed (Spec D.9).
func (p *Plan) IsStale(currentConfigHash string, currentVersions map[string]string) bool {
	if p.ConfigHash != currentConfigHash {
		return true
	}
	for svc, ver := range p.BaselineVersions {
		if currentVersions[svc] != ver {
			return true
		}
	}
	return false
}
