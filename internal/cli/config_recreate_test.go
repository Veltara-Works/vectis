package cli

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/engine"
)

const liveCompose = `services:
  api:
    image: ghcr.io/veltara-works/vectis-api:v0.1.57
    mem_limit: 512m
  rspamd:
    image: ghcr.io/veltara-works/vectis-rspamd:v0.1.57
  clamav:
    image: ghcr.io/veltara-works/vectis-clamav:v0.1.57
  orchestrator:
    image: ghcr.io/veltara-works/vectis-orchestrator:v0.1.57
`

const renderedCompose = `services:
  api:
    image: ghcr.io/veltara-works/vectis-api:v0.1.57
    mem_limit: 1g
  rspamd:
    image: ghcr.io/veltara-works/vectis-rspamd:v0.1.57
  webmail:
    image: ghcr.io/veltara-works/vectis-webmail:v0.1.57
  orchestrator:
    image: ghcr.io/veltara-works/vectis-orchestrator:v0.1.57
    mem_limit: 256m
`

func TestPlanRecreate(t *testing.T) {
	p, err := planRecreate([]byte(liveCompose), []byte(renderedCompose), recreatePlan{})
	if err != nil {
		t.Fatal(err)
	}
	want := recreatePlan{Services: []string{"api", "webmail"}, Removed: []string{"clamav"}, OrchestratorChanged: true}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("plan = %+v, want %+v", p, want)
	}

	// Nothing changed in the compose, but an earlier run left rspamd and a
	// no-longer-defined service pending, plus a removal that's been undone.
	pending := recreatePlan{Services: []string{"rspamd", "gone-svc"}, Removed: []string{"api", "loki"}}
	p, err = planRecreate([]byte(renderedCompose), []byte(renderedCompose), pending)
	if err != nil {
		t.Fatal(err)
	}
	want = recreatePlan{Services: []string{"rspamd"}, Removed: []string{"loki"}}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("plan with pending = %+v, want %+v", p, want)
	}

	if p, err := planRecreate([]byte(renderedCompose), []byte(renderedCompose), recreatePlan{}); err != nil || !p.empty() || p.OrchestratorChanged {
		t.Fatalf("no change: plan=%+v err=%v", p, err)
	}
}

func TestSupersedeActions(t *testing.T) {
	in := []engine.ServiceAction{
		{Service: "postfix", Action: "reload", Reason: "postfix/main.cf"},
		{Service: "rspamd", Action: "restart", Reason: "rspamd/x"},
		{Service: "dovecot", Action: "none"},
	}
	out := supersedeActions(in, recreatePlan{Services: []string{"rspamd"}})
	if out[0].Action != "reload" || out[1].Action != "none" || out[1].Reason != "superseded by recreate" || out[2].Action != "none" {
		t.Fatalf("actions = %+v", out)
	}
	if in[1].Action != "restart" {
		t.Error("input slice must not be modified")
	}
}

func TestRecreatePendingRoundTrip(t *testing.T) {
	dir := t.TempDir()
	if p, err := readRecreatePending(dir); err != nil || !p.empty() {
		t.Fatalf("no file: %+v %v", p, err)
	}
	want := recreatePlan{Services: []string{"api"}, Removed: []string{"clamav"}}
	if err := writeRecreatePending(dir, want); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, recreatePendingFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("pending file mode: %v %v", st, err)
	}
	if got, err := readRecreatePending(dir); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("read back %+v %v", got, err)
	}
	if err := clearRecreatePending(dir); err != nil {
		t.Fatal(err)
	}
	if err := clearRecreatePending(dir); err != nil {
		t.Fatalf("clearing twice must not fail: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, recreatePendingFile), []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readRecreatePending(dir); err == nil {
		t.Error("corrupt pending file: want error")
	}
}

func TestBackupLiveCompose(t *testing.T) {
	dir := t.TempDir()
	if p, err := backupLiveCompose(dir, nil, time.Now()); err != nil || p != "" {
		t.Fatalf("no live compose: %q %v", p, err)
	}
	p, err := backupLiveCompose(dir, []byte(liveCompose), time.Date(2026, 10, 17, 6, 30, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(p, "docker-compose.yml.pre-config-apply-20261017T063000Z") {
		t.Errorf("backup path %q", p)
	}
	if b, _ := os.ReadFile(p); string(b) != liveCompose {
		t.Error("backup content differs")
	}
}

func TestLiveAndRenderedCompose(t *testing.T) {
	dir := t.TempDir()
	files := []engine.GeneratedFile{{RelPath: composeRelPath, Content: []byte(renderedCompose)}}
	live, rendered, err := liveAndRenderedCompose(dir, files)
	if err != nil || live != nil || string(rendered) != renderedCompose {
		t.Fatalf("fresh install: live=%q err=%v", live, err)
	}
	if err := os.WriteFile(filepath.Join(dir, composeRelPath), []byte(liveCompose), 0o600); err != nil {
		t.Fatal(err)
	}
	if live, _, err := liveAndRenderedCompose(dir, files); err != nil || string(live) != liveCompose {
		t.Fatalf("live read: %q %v", live, err)
	}
}
