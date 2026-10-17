package engine

import (
	"regexp"
	"strings"
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
