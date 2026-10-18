package engine

import (
	"regexp"
	"strings"
	"testing"
)

const (
	pinA = "@sha256:" + "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
	pinB = "@sha256:" + "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
	pinP = "@sha256:" + "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3"
)

func TestCarryComposeImagePins(t *testing.T) {
	rendered := `services:
  api:
    image: ghcr.io/veltara-works/vectis-api:v0.1.56
  rspamd:
    image: ghcr.io/veltara-works/vectis-rspamd:v0.1.56
  dovecot:
    image: ghcr.io/veltara-works/vectis-dovecot:v0.1.57
  postfix:
    image: ghcr.io/veltara-works/vectis-postfix:v0.1.56` + pinB + `
  postgres:
    image: postgres:17-alpine
`
	live := `services:
  api:
    image: ghcr.io/veltara-works/vectis-api:v0.1.56` + pinA + `
  rspamd:
    image: ghcr.io/veltara-works/vectis-rspamd:v0.1.56
  dovecot:
    image: ghcr.io/veltara-works/vectis-dovecot:v0.1.56` + pinA + `
  postfix:
    image: ghcr.io/veltara-works/vectis-postfix:v0.1.56` + pinA + `
  postgres:
    image: postgres:17-alpine` + pinP + `
`
	got := string(CarryComposeImagePins([]byte(rendered), []byte(live)))

	for _, c := range []struct{ name, want string }{
		{"same tag: pin carried", "vectis-api:v0.1.56" + pinA + "\n"},
		{"live unpinned: stays tag-only", "vectis-rspamd:v0.1.56\n"},
		{"different tag: old pin NOT carried", "vectis-dovecot:v0.1.57\n"},
		{"already pinned by the renderer: untouched", "vectis-postfix:v0.1.56" + pinB + "\n"},
		{"non-vectis image: untouched", "image: postgres:17-alpine\n"},
	} {
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: missing %q in\n%s", c.name, c.want, got)
		}
	}
	if unc := UncarriedComposeImagePins([]byte(got), []byte(live)); len(unc) != 1 || unc[0] != "dovecot" {
		t.Errorf("uncarried = %v, want [dovecot] (tag differs; rspamd was never pinned)", unc)
	}
	if n := ComposeImagePinCount([]byte(got)); n != 2 {
		t.Errorf("pin count = %d, want 2 (api carried + postfix rendered)", n)
	}

	if out := CarryComposeImagePins([]byte(rendered), nil); string(out) != rendered {
		t.Error("no live compose: rendered bytes must come back unchanged")
	}
}

// The #262 acceptance test: re-rendering an unchanged config over a compose
// `vectis update apply` pinned must give back the live file byte for byte.
func TestCarryComposeImagePins_UnchangedConfigIsByteIdentical(t *testing.T) {
	data := testData()
	data.Version = "v0.1.56" // testData leaves it empty, which renders tagless images
	files, err := Generate(data)
	if err != nil {
		t.Fatal(err)
	}
	var rendered []byte
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			rendered = f.Content
		}
	}
	if rendered == nil {
		t.Fatal("docker-compose.yml not generated")
	}

	// Pin every vectis-* image the way update apply does.
	re := regexp.MustCompile(`(?m)^([ \t]*image:[ \t]*ghcr\.io/veltara-works/vectis-[a-z0-9-]+:[^@\s]+)[ \t]*$`)
	live := re.ReplaceAll(rendered, []byte("${1}"+pinA))
	n := ComposeImagePinCount(live)
	if n < 5 {
		t.Fatalf("expected the rendered compose to have several vectis images, pinned %d", n)
	}

	if got := CarryComposeImagePins(rendered, live); string(got) != string(live) {
		t.Fatalf("re-render over a pinned compose is not byte-identical (pins %d → %d)", n, ComposeImagePinCount(got))
	}
}

func TestComposeImageTagMismatchesAndPinning(t *testing.T) {
	live := "services:\n  api:\n    image: ghcr.io/veltara-works/vectis-api:v0.1.57" + pinA + "\n  rspamd:\n    image: ghcr.io/veltara-works/vectis-rspamd:v0.1.57\n"
	same := "services:\n  api:\n    image: ghcr.io/veltara-works/vectis-api:v0.1.57\n  rspamd:\n    image: ghcr.io/veltara-works/vectis-rspamd:v0.1.57\n  webmail:\n    image: ghcr.io/veltara-works/vectis-webmail:v0.1.57\n"
	if mm, err := ComposeImageTagMismatches([]byte(same), []byte(live)); err != nil || len(mm) != 0 {
		t.Errorf("same release: mismatches %v, err %v", mm, err)
	}
	other := strings.ReplaceAll(same, "v0.1.57", "v0.1.58")
	mm, err := ComposeImageTagMismatches([]byte(other), []byte(live))
	if err != nil {
		t.Fatal(err)
	}
	if len(mm) != 2 || mm[0] != "api (v0.1.57 → v0.1.58)" || mm[1] != "rspamd (v0.1.57 → v0.1.58)" {
		t.Errorf("mismatches = %v (webmail is new, not a mismatch)", mm)
	}

	carried := CarryComposeImagePins([]byte(same), []byte(live))
	if un := UnpinnedComposeImages(carried); len(un) != 2 || un[0] != "rspamd" || un[1] != "webmail" {
		t.Fatalf("unpinned = %v", un)
	}
	pinned := string(PinComposeImages(carried, map[string]string{"webmail": strings.TrimPrefix(pinB, "@"), "api": strings.TrimPrefix(pinP, "@")}))
	if !strings.Contains(pinned, "vectis-webmail:v0.1.57"+pinB+"\n") {
		t.Errorf("webmail not pinned:\n%s", pinned)
	}
	if !strings.Contains(pinned, "vectis-api:v0.1.57"+pinA+"\n") {
		t.Errorf("an existing pin must not be replaced:\n%s", pinned)
	}
	if !strings.Contains(pinned, "vectis-rspamd:v0.1.57\n") {
		t.Errorf("rspamd has no digest in the map and must stay as it was:\n%s", pinned)
	}
}

// A hand-edited live compose (quoted image values, trailing comments) must not
// hide a release mismatch, and an unparseable one must fail closed (Copilot, #297).
func TestComposeImageTagMismatchesDecodesYAML(t *testing.T) {
	live := "services:\n" +
		"  api:\n    image: \"ghcr.io/veltara-works/vectis-api:v0.1.57" + pinA + "\"\n" +
		"  rspamd:\n    image: 'ghcr.io/veltara-works/vectis-rspamd:v0.1.57' # pinned by hand\n" +
		"  postfix:\n    image: ghcr.io/veltara-works/vectis-postfix:v0.1.57   # note\n" +
		"  traefik:\n    image: traefik:v3.6\n"
	rendered := "services:\n" +
		"  api:\n    image: ghcr.io/veltara-works/vectis-api:v0.1.58\n" +
		"  rspamd:\n    image: ghcr.io/veltara-works/vectis-rspamd:v0.1.58\n" +
		"  postfix:\n    image: ghcr.io/veltara-works/vectis-postfix:v0.1.58\n" +
		"  traefik:\n    image: traefik:v3.7\n"
	mm, err := ComposeImageTagMismatches([]byte(rendered), []byte(live))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api (v0.1.57 → v0.1.58)", "postfix (v0.1.57 → v0.1.58)", "rspamd (v0.1.57 → v0.1.58)"}
	if strings.Join(mm, "|") != strings.Join(want, "|") {
		t.Errorf("mismatches = %v, want %v", mm, want)
	}

	if mm, err := ComposeImageTagMismatches([]byte(rendered), nil); err != nil || len(mm) != 0 {
		t.Errorf("no live compose: %v, %v", mm, err)
	}
	if _, err := ComposeImageTagMismatches([]byte(rendered), []byte("services: [\n")); err == nil {
		t.Error("unparseable live compose must be an error")
	}
}
