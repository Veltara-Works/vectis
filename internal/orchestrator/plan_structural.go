package orchestrator

import (
	"context"
	"fmt"

	"gopkg.in/yaml.v3"
)

// detectStructuralChanges renders the desired compose via composeGen and
// compares its service set against the on-disk compose to surface structural
// diffs that the image-version loop alone cannot see.
//
// The image-version loop in Plan() iterates VectisImageServices and emits an
// "update" PlanChange when a service's running image differs from the on-disk
// compose image. That works for tag bumps, but returns no changes when:
//
//   - clamav.profile flips between "none" (block omitted) and any other
//     profile (block included). On-disk compose has no clamav service to
//     diff against, so the image-version loop produces nothing.
//   - any other profile-gated or optional service appears or disappears
//     under config.yaml control.
//
// Plan.IsEmpty() returning true short-circuits Apply before Phase 3.5
// (RegenerateCompose), so the config.yaml change never lands on disk and
// the new container never starts. The fix: also diff the compose service
// set. Services in rendered-but-not-disk emit "create" changes; services
// in disk-but-not-rendered emit "remove" changes. The synthetic changes
// make IsEmpty() false; Phase 3.5 regenerates compose; Phase 4.x picks up
// the new shape.
//
// Scope is intentionally narrow for v1:
//   - Only VectisImageServices participate. External services
//     (postgres/valkey/traefik) have stable presence and aren't config-
//     driven, so they'd add noise.
//   - Mount/env/port-only structural diffs are out of scope. This covers
//     profile-gating, which is the user-visible bug.
//
// Failures are best-effort: composeGen unset (legacy installs without v0.1.6
// wiring) or render errors return no changes plus a warning that surfaces
// in the Plan response. The image-version loop still carries the rest of
// the plan.
func (o *Orchestrator) detectStructuralChanges(
	ctx context.Context,
	releaseTag string,
	diskImages map[string]string,
) ([]PlanChange, []string) {
	if o.composeGen == nil {
		return nil, nil
	}

	rendered, err := o.composeGen(ctx, releaseTag)
	if err != nil {
		o.logger.Warn("structural plan: compose render failed; skipping structural diff",
			"error", err, "release_tag", releaseTag)
		return nil, []string{
			fmt.Sprintf("compose render failed during plan; profile-gated service changes (e.g. clamav) may be missed: %v", err),
		}
	}

	renderedSvcs, err := parseComposeServiceImages(rendered)
	if err != nil {
		o.logger.Warn("structural plan: parse rendered compose failed; skipping structural diff",
			"error", err)
		return nil, []string{
			fmt.Sprintf("rendered compose unparseable; profile-gated service changes may be missed: %v", err),
		}
	}

	var out []PlanChange
	for _, svc := range VectisImageServices {
		_, inDisk := diskImages[svc]
		renderedImg, inRendered := renderedSvcs[svc]
		switch {
		case inDisk && !inRendered:
			out = append(out, PlanChange{
				Service:  svc,
				Type:     "remove",
				OldImage: diskImages[svc],
				Detail:   "service no longer rendered by current config.yaml; will be removed on Apply",
			})
		case !inDisk && inRendered:
			out = append(out, PlanChange{
				Service:  svc,
				Type:     "create",
				NewImage: renderedImg,
				Detail:   "service newly rendered by current config.yaml; will be added on Apply",
			})
		}
	}
	return out, nil
}

// parseComposeServiceImages extracts the {service: image} map from a rendered
// compose YAML blob. Operates on an in-memory buffer (unlike
// DockerManager.composeImages which shells out to `docker compose config`),
// so it works on output from ComposeGenerator without needing a temp file.
func parseComposeServiceImages(data []byte) (map[string]string, error) {
	var parsed struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(parsed.Services))
	for name, svc := range parsed.Services {
		out[name] = svc.Image
	}
	return out, nil
}
