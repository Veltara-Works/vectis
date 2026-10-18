package engine

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// vectisImagePrefix is the registry path of the Vectis service images.
const vectisImagePrefix = "ghcr.io/veltara-works/vectis-"

// composeVectisImageRe matches a vectis-* `image:` line in a compose file:
// prefix, repo, service, ":tag" (optional), "@sha256:digest" (optional). The
// same shape the orchestrator pins (internal/orchestrator/compose_rewrite.go).
var composeVectisImageRe = regexp.MustCompile(
	`(?m)^([ \t]*image:[ \t]*)(` + regexp.QuoteMeta(vectisImagePrefix) + `([a-z0-9-]+))(:[^@\s]+)?(@sha256:[0-9a-f]{64})?[ \t]*$`,
)

// CarryComposeImagePins copies the `@sha256` digest pins from the live compose
// onto a freshly rendered one (#262). Templates render vectis-* images by tag
// only; `vectis update apply` pins each to its signed manifest digest. Without
// this, `vectis config apply` re-renders the live compose and silently drops
// every pin.
//
// A pin is carried only when the live line names the same image repo AND the
// same tag as the rendered one, so an old digest is never attached to a
// different version. Lines the renderer already pinned, and every non-vectis
// image, are left as rendered. With no live compose (or no pins in it) the
// rendered bytes come back unchanged.
func CarryComposeImagePins(rendered, live []byte) []byte {
	type pin struct{ tag, digest string }
	pins := map[string]pin{}
	for _, m := range composeVectisImageRe.FindAllStringSubmatch(string(live), -1) {
		if m[5] != "" {
			pins[m[3]] = pin{tag: m[4], digest: m[5]}
		}
	}
	if len(pins) == 0 {
		return rendered
	}
	return []byte(composeVectisImageRe.ReplaceAllStringFunc(string(rendered), func(line string) string {
		m := composeVectisImageRe.FindStringSubmatch(line)
		prefix, repo, svc, tag, digest := m[1], m[2], m[3], m[4], m[5]
		p, ok := pins[svc]
		if digest != "" || !ok || p.tag != tag || tag == "" {
			return line
		}
		return prefix + repo + tag + p.digest
	}))
}

// UncarriedComposeImagePins lists the services (sorted) that are pinned in the
// live compose and still present in the rendered one, but whose rendered image
// line has no digest: their tag differs, so CarryComposeImagePins didn't copy
// the pin. A service dropped from the rendered compose (e.g. webmail switched
// off) is not listed.
func UncarriedComposeImagePins(rendered, live []byte) []string {
	pinned := map[string]bool{}
	for _, m := range composeVectisImageRe.FindAllStringSubmatch(string(live), -1) {
		if m[5] != "" {
			pinned[m[3]] = true
		}
	}
	var out []string
	for _, m := range composeVectisImageRe.FindAllStringSubmatch(string(rendered), -1) {
		if pinned[m[3]] && m[5] == "" {
			out = append(out, m[3])
		}
	}
	sort.Strings(out)
	return out
}

// ComposeImagePinCount reports how many vectis-* image lines carry a digest.
func ComposeImagePinCount(compose []byte) int {
	n := 0
	for _, m := range composeVectisImageRe.FindAllStringSubmatch(string(compose), -1) {
		if strings.HasPrefix(m[5], "@sha256:") {
			n++
		}
	}
	return n
}

// ComposeImageTagMismatches lists vectis-* services present in both composes
// whose image tag differs, as "svc (live → rendered)", sorted. A non-empty
// result means the rendering CLI is a different release than the running
// stack: writing that compose would change versions outside `vectis update
// apply` (no snapshot, no migrations, orchestrator left behind).
//
// It compares decoded YAML image values, not lines, so a hand-edited live
// compose (quoted value, trailing comment) can't hide a mismatch, and it fails
// closed: a compose it can't parse is an error.
func ComposeImageTagMismatches(rendered, live []byte) ([]string, error) {
	liveTags, err := composeVectisImageTags(live)
	if err != nil {
		return nil, fmt.Errorf("live compose: %w", err)
	}
	renderedTags, err := composeVectisImageTags(rendered)
	if err != nil {
		return nil, fmt.Errorf("rendered compose: %w", err)
	}
	var out []string
	for svc, rt := range renderedTags {
		if lt, ok := liveTags[svc]; ok && lt != rt {
			out = append(out, fmt.Sprintf("%s (%s → %s)", svc, lt, rt))
		}
	}
	sort.Strings(out)
	return out, nil
}

// composeVectisImageTags decodes a compose file and returns compose service →
// tag ("" when untagged) for each service running a vectis-* image. An empty
// compose (no live file yet) has none.
func composeVectisImageTags(compose []byte) (map[string]string, error) {
	var doc struct {
		Services map[string]struct {
			Image string `yaml:"image"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal(compose, &doc); err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	tags := map[string]string{}
	for svc, s := range doc.Services {
		ref := strings.TrimSpace(s.Image)
		if !strings.HasPrefix(strings.ToLower(ref), vectisImagePrefix) {
			continue
		}
		ref, _, _ = strings.Cut(ref, "@") // drop any digest pin
		tag := ""
		if i := strings.LastIndex(ref, ":"); i > len(vectisImagePrefix) {
			tag = ref[i+1:]
		}
		tags[svc] = tag
	}
	return tags, nil
}

// UnpinnedComposeImages lists the vectis-* services whose image line has no
// digest, sorted.
func UnpinnedComposeImages(compose []byte) []string {
	var out []string
	for _, m := range composeVectisImageRe.FindAllStringSubmatch(string(compose), -1) {
		if m[5] == "" {
			out = append(out, m[3])
		}
	}
	sort.Strings(out)
	return out
}

// PinComposeImages adds `@<digest>` to each unpinned vectis-* image line whose
// service is in digests (service → "sha256:…", as a signed release manifest
// lists them). Already-pinned lines are left alone.
func PinComposeImages(compose []byte, digests map[string]string) []byte {
	return []byte(composeVectisImageRe.ReplaceAllStringFunc(string(compose), func(line string) string {
		m := composeVectisImageRe.FindStringSubmatch(line)
		d, ok := digests[m[3]]
		if m[5] != "" || !ok || m[4] == "" {
			return line
		}
		return m[1] + m[2] + m[4] + "@" + d
	}))
}

// ComposeImageTag returns the tag of the first vectis-* image in the compose
// (all of them carry the release tag), or "" if there is none.
func ComposeImageTag(compose []byte) string {
	if m := composeVectisImageRe.FindStringSubmatch(string(compose)); m != nil {
		return strings.TrimPrefix(m[4], ":")
	}
	return ""
}
