package orchestrator

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"sort"
	"testing"
)

func TestParseComposeServiceImages(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		want    map[string]string
		wantErr bool
	}{
		{
			name: "basic two services",
			yaml: `services:
  api:
    image: ghcr.io/x/api:v1
  postfix:
    image: ghcr.io/x/postfix:v1
`,
			want: map[string]string{
				"api":     "ghcr.io/x/api:v1",
				"postfix": "ghcr.io/x/postfix:v1",
			},
		},
		{
			name: "service without image is recorded with empty image",
			yaml: `services:
  api:
    image: ghcr.io/x/api:v1
  postgres:
    build: ./postgres
`,
			want: map[string]string{
				"api":      "ghcr.io/x/api:v1",
				"postgres": "",
			},
		},
		{
			name:    "garbage yaml",
			yaml:    "this is: not\n  valid: : yaml:",
			wantErr: true,
		},
		{
			name: "no services key",
			yaml: `version: "3.8"
networks:
  vectis: {}
`,
			want: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseComposeServiceImages([]byte(tt.yaml))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil; result=%v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// orchForStructuralTest builds the minimum Orchestrator state needed to
// exercise detectStructuralChanges without constructing the full DB / Valkey
// / Docker stack.
func orchForStructuralTest(gen ComposeGenerator) *Orchestrator {
	return &Orchestrator{
		composeGen: gen,
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func sortChanges(c []PlanChange) {
	sort.Slice(c, func(i, j int) bool { return c[i].Service < c[j].Service })
}

func TestDetectStructuralChanges_NilComposeGen(t *testing.T) {
	o := orchForStructuralTest(nil)
	changes, warns := o.detectStructuralChanges(context.Background(), "v1", map[string]string{
		"clamav": "ghcr.io/x/clamav:v1",
	})
	if len(changes) != 0 {
		t.Errorf("expected no changes when composeGen is nil, got %d", len(changes))
	}
	if len(warns) != 0 {
		t.Errorf("expected no warnings when composeGen is nil, got %v", warns)
	}
}

func TestDetectStructuralChanges_RenderError(t *testing.T) {
	o := orchForStructuralTest(func(_ context.Context, _ string) ([]byte, error) {
		return nil, errors.New("render boom")
	})
	changes, warns := o.detectStructuralChanges(context.Background(), "v1", map[string]string{})
	if len(changes) != 0 {
		t.Errorf("expected no changes on render error, got %d", len(changes))
	}
	if len(warns) != 1 {
		t.Fatalf("expected exactly one warning on render error, got %d: %v", len(warns), warns)
	}
}

func TestDetectStructuralChanges_ClamAVCreate(t *testing.T) {
	// Disk has no clamav (profile was "none"); rendered now has it
	// (profile flipped to "production"). Expect a "create" PlanChange.
	rendered := []byte(`services:
  api:
    image: ghcr.io/x/api:v1
  clamav:
    image: ghcr.io/x/clamav:v1
  postfix:
    image: ghcr.io/x/postfix:v1
`)
	o := orchForStructuralTest(func(_ context.Context, _ string) ([]byte, error) {
		return rendered, nil
	})

	disk := map[string]string{
		"api":     "ghcr.io/x/api:v1",
		"postfix": "ghcr.io/x/postfix:v1",
	}

	changes, warns := o.detectStructuralChanges(context.Background(), "v1", disk)
	if len(warns) != 0 {
		t.Errorf("expected no warnings, got %v", warns)
	}
	sortChanges(changes)
	if len(changes) != 1 {
		t.Fatalf("expected exactly 1 change, got %d: %+v", len(changes), changes)
	}
	c := changes[0]
	if c.Service != "clamav" {
		t.Errorf("got service %q, want clamav", c.Service)
	}
	if c.Type != "create" {
		t.Errorf("got type %q, want create", c.Type)
	}
	if c.NewImage != "ghcr.io/x/clamav:v1" {
		t.Errorf("got new_image %q, want ghcr.io/x/clamav:v1", c.NewImage)
	}
	if c.Detail == "" {
		t.Error("expected non-empty Detail explaining why")
	}
}

func TestDetectStructuralChanges_ClamAVRemove(t *testing.T) {
	// Disk has clamav; rendered doesn't (profile flipped to "none").
	// Expect a "remove" PlanChange.
	rendered := []byte(`services:
  api:
    image: ghcr.io/x/api:v1
  postfix:
    image: ghcr.io/x/postfix:v1
`)
	o := orchForStructuralTest(func(_ context.Context, _ string) ([]byte, error) {
		return rendered, nil
	})

	disk := map[string]string{
		"api":     "ghcr.io/x/api:v1",
		"clamav":  "ghcr.io/x/clamav:v1",
		"postfix": "ghcr.io/x/postfix:v1",
	}

	changes, _ := o.detectStructuralChanges(context.Background(), "v1", disk)
	if len(changes) != 1 {
		t.Fatalf("expected exactly 1 change, got %d: %+v", len(changes), changes)
	}
	c := changes[0]
	if c.Service != "clamav" || c.Type != "remove" {
		t.Errorf("got %+v, want service=clamav type=remove", c)
	}
	if c.OldImage != "ghcr.io/x/clamav:v1" {
		t.Errorf("got old_image %q, want ghcr.io/x/clamav:v1", c.OldImage)
	}
}

func TestDetectStructuralChanges_NoDiff(t *testing.T) {
	// Disk and rendered have the same service set — no structural change.
	// (Image-version drift is the responsibility of the loop in Plan(),
	//  not detectStructuralChanges.)
	rendered := []byte(`services:
  api:
    image: ghcr.io/x/api:v2
  clamav:
    image: ghcr.io/x/clamav:v2
`)
	o := orchForStructuralTest(func(_ context.Context, _ string) ([]byte, error) {
		return rendered, nil
	})

	disk := map[string]string{
		"api":    "ghcr.io/x/api:v1",
		"clamav": "ghcr.io/x/clamav:v1",
	}

	changes, warns := o.detectStructuralChanges(context.Background(), "v2", disk)
	if len(changes) != 0 {
		t.Errorf("expected no structural changes when service set matches; got %+v", changes)
	}
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
}

func TestDetectStructuralChanges_OnlyVectisImageServices(t *testing.T) {
	// External services (postgres/valkey/traefik) appearing in only one
	// side must NOT generate changes — they're outside Plan's scope.
	rendered := []byte(`services:
  api:
    image: ghcr.io/x/api:v1
  postgres:
    image: postgres:17-alpine
`)
	o := orchForStructuralTest(func(_ context.Context, _ string) ([]byte, error) {
		return rendered, nil
	})

	// disk has neither postgres nor api yet (impossible state, used to
	// isolate the "external services don't drive structural changes" check).
	disk := map[string]string{}

	changes, _ := o.detectStructuralChanges(context.Background(), "v1", disk)
	// Expect exactly one change — for `api` (a VectisImageService).
	// Postgres should NOT appear despite being only-in-rendered.
	if len(changes) != 1 || changes[0].Service != "api" {
		t.Errorf("expected exactly one change for `api`, got %+v", changes)
	}
}
