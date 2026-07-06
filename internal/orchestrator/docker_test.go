package orchestrator

import (
	"reflect"
	"strings"
	"testing"
)

func TestIsLocalImageRef(t *testing.T) {
	tests := []struct {
		name  string
		image string
		local bool
	}{
		{"empty string", "", true},
		{"bare name no tag", "postgres", true},
		{"bare name with dev tag", "vectis-api:dev", true},
		{"bare name with hub-style tag", "postgres:17-alpine", true},
		{"library namespace", "library/postgres:17", false},
		{"ghcr.io reference", "ghcr.io/veltara-works/vectis-api:latest", false},
		{"docker.io reference", "docker.io/library/postgres:17-alpine", false},
		{"quay.io reference", "quay.io/coreos/etcd:v3.5", false},
		{"localhost registry", "localhost:5000/myapp:1.0", false},
		{"localhost no port", "localhost/myapp:1.0", false},
		{"private registry with port", "registry.example.com:5000/app:1", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isLocalImageRef(tc.image)
			if got != tc.local {
				t.Errorf("isLocalImageRef(%q) = %v, want %v", tc.image, got, tc.local)
			}
		})
	}
}

// TestVectisProvenanceTargets covers the REL-3 Part B image selection: only
// sha256-digested entries are verified, refs are the canonical vectis-* @digest
// form, and the order is stable (sorted by service).
func TestVectisProvenanceTargets(t *testing.T) {
	t.Run("nil and empty are no-ops", func(t *testing.T) {
		if got := vectisProvenanceTargets(nil); len(got) != 0 {
			t.Errorf("nil digests = %v, want empty", got)
		}
		if got := vectisProvenanceTargets(map[string]string{}); len(got) != 0 {
			t.Errorf("empty digests = %v, want empty", got)
		}
	})

	t.Run("builds sorted sha256 refs and drops non-sha256", func(t *testing.T) {
		digests := map[string]string{
			"api":     "sha256:" + strings.Repeat("a", 64),
			"dovecot": "sha256:" + strings.Repeat("b", 64),
			"webmail": "v0.1.42", // not a digest → must be dropped
		}
		want := []provenanceTarget{
			{Service: "api", ImageRef: "ghcr.io/veltara-works/vectis-api@sha256:" + strings.Repeat("a", 64)},
			{Service: "dovecot", ImageRef: "ghcr.io/veltara-works/vectis-dovecot@sha256:" + strings.Repeat("b", 64)},
		}
		got := vectisProvenanceTargets(digests)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("vectisProvenanceTargets =\n  %#v\nwant\n  %#v", got, want)
		}
	})
}

// TestCosignVerifyArgs pins the exact cosign invocation: the pinned (digest-
// bearing) cosign image, keyless verify, and the release-workflow identity +
// GitHub OIDC issuer. A regression here would silently weaken provenance.
func TestCosignVerifyArgs(t *testing.T) {
	ref := "ghcr.io/veltara-works/vectis-api@sha256:" + strings.Repeat("c", 64)
	args := cosignVerifyArgs(ref)

	joined := strings.Join(args, " ")
	for _, want := range []string{
		"run --rm " + cosignImage,
		"verify",
		"--certificate-identity-regexp " + cosignCertIdentityRegexp,
		"--certificate-oidc-issuer " + cosignCertOIDCIssuer,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("cosign args missing %q; got: %s", want, joined)
		}
	}
	// The image ref must be the final argument (cosign's positional target).
	if args[len(args)-1] != ref {
		t.Errorf("last arg = %q, want image ref %q", args[len(args)-1], ref)
	}
	// The verifier image itself must be digest-pinned — a floating cosign tag
	// would defeat the point of verifying anything.
	if !strings.Contains(cosignImage, "@sha256:") {
		t.Errorf("cosignImage %q must be digest-pinned (@sha256:)", cosignImage)
	}
	// Identity must be anchored to our release workflow, not any GitHub workflow.
	if !strings.Contains(cosignCertIdentityRegexp, "Veltara-Works/vectis") ||
		!strings.HasPrefix(cosignCertIdentityRegexp, "^") {
		t.Errorf("cert-identity regexp not anchored to the vectis release workflow: %q", cosignCertIdentityRegexp)
	}
}
