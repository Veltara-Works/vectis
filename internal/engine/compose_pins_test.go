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
