package engine

import (
	"reflect"
	"testing"
)

func TestComposeServiceChanges(t *testing.T) {
	old := `services:
  api:
    image: ghcr.io/veltara-works/vectis-api:v0.1.57
    mem_limit: 512m
  rspamd:
    image: ghcr.io/veltara-works/vectis-rspamd:v0.1.57
    environment:
      - A=1
      - B=2
  clamav:
    image: ghcr.io/veltara-works/vectis-clamav:v0.1.57
  postfix:
    image: ghcr.io/veltara-works/vectis-postfix:v0.1.57
    healthcheck: {test: ["CMD", "true"], interval: 30s}
`
	// Reformatted and re-commented, with key order changed for postfix: not a change.
	newer := `# rendered by vectis config apply
services:
  postfix:
    healthcheck:
      interval: 30s
      test: ["CMD", "true"]
    image: ghcr.io/veltara-works/vectis-postfix:v0.1.57
  api:
    image: ghcr.io/veltara-works/vectis-api:v0.1.57
    mem_limit: 1g
  rspamd:
    image: ghcr.io/veltara-works/vectis-rspamd:v0.1.57
    environment:
      - A=1
      - B=3
  webmail:
    image: ghcr.io/veltara-works/vectis-webmail:v0.1.57
`
	changed, added, removed, err := ComposeServiceChanges([]byte(old), []byte(newer))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(changed, []string{"api", "rspamd"}) {
		t.Errorf("changed = %v, want [api rspamd]", changed)
	}
	if !reflect.DeepEqual(added, []string{"webmail"}) {
		t.Errorf("added = %v, want [webmail]", added)
	}
	if !reflect.DeepEqual(removed, []string{"clamav"}) {
		t.Errorf("removed = %v, want [clamav]", removed)
	}

	c, a, r, err := ComposeServiceChanges([]byte(old), []byte(old))
	if err != nil || len(c)+len(a)+len(r) != 0 {
		t.Errorf("identical compose: %v %v %v %v", c, a, r, err)
	}

	_, a, _, err = ComposeServiceChanges(nil, []byte(newer))
	if err != nil || len(a) != 4 {
		t.Errorf("fresh install: added=%v err=%v, want all 4 services", a, err)
	}

	if _, _, _, err := ComposeServiceChanges([]byte("services: [unclosed"), []byte(newer)); err == nil {
		t.Error("unparseable live compose: want error")
	}
}

// A real render diffed against itself (with pins carried) changes nothing.
func TestComposeServiceChanges_RealRenderStable(t *testing.T) {
	data := testData()
	data.Version = "v0.1.57"
	files, err := Generate(data)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if f.RelPath == "docker-compose.yml" {
			c, a, r, err := ComposeServiceChanges(f.Content, f.Content)
			if err != nil || len(c)+len(a)+len(r) != 0 {
				t.Fatalf("self-diff: changed=%v added=%v removed=%v err=%v", c, a, r, err)
			}
			return
		}
	}
	t.Fatal("docker-compose.yml not generated")
}
