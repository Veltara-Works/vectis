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

const renderedComposeFixture = `services:
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
	p, err := planRecreate([]byte(liveCompose), []byte(renderedComposeFixture), recreatePlan{})
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
	p, err = planRecreate([]byte(renderedComposeFixture), []byte(renderedComposeFixture), pending)
	if err != nil {
		t.Fatal(err)
	}
	want = recreatePlan{Services: []string{"rspamd"}, Removed: []string{"loki"}}
	if !reflect.DeepEqual(p, want) {
		t.Fatalf("plan with pending = %+v, want %+v", p, want)
	}

	if p, err := planRecreate([]byte(renderedComposeFixture), []byte(renderedComposeFixture), recreatePlan{}); err != nil || !p.empty() || p.OrchestratorChanged {
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
	files := []engine.GeneratedFile{{RelPath: composeRelPath, Content: []byte(renderedComposeFixture)}}
	live, rendered, err := liveAndRenderedCompose(dir, files)
	if err != nil || live != nil || string(rendered) != renderedComposeFixture {
		t.Fatalf("fresh install: live=%q err=%v", live, err)
	}
	if err := os.WriteFile(filepath.Join(dir, composeRelPath), []byte(liveCompose), 0o600); err != nil {
		t.Fatal(err)
	}
	if live, _, err := liveAndRenderedCompose(dir, files); err != nil || string(live) != liveCompose {
		t.Fatalf("live read: %q %v", live, err)
	}
}

func TestLockConfigApply(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockConfigApply(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockConfigApply(dir); err == nil || !strings.Contains(err.Error(), "another `vectis config apply` is running") {
		t.Fatalf("second lock: err = %v", err)
	}
	unlock()
	unlock2, err := lockConfigApply(dir)
	if err != nil {
		t.Fatalf("lock after unlock: %v", err)
	}
	unlock2()
}

func TestPinNewServices(t *testing.T) {
	const pinned = "@sha256:e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"
	const dWeb = "sha256:f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6"
	live := []byte("services:\n  api:\n    image: ghcr.io/veltara-works/vectis-api:v0.1.57" + pinned + "\n")
	rendered := "services:\n  api:\n    image: ghcr.io/veltara-works/vectis-api:v0.1.57" + pinned + "\n  webmail:\n    image: ghcr.io/veltara-works/vectis-webmail:v0.1.57\n"
	files := func() []engine.GeneratedFile {
		return []engine.GeneratedFile{{RelPath: composeRelPath, Content: []byte(rendered)}}
	}
	orig := manifestDigests
	defer func() { manifestDigests = orig }()

	var askedTag string
	manifestDigests = func(tag string) (map[string]string, error) {
		askedTag = tag
		return map[string]string{"webmail": dWeb, "api": "sha256:ignored"}, nil
	}
	fs1 := files()
	if err := pinNewServices(fs1, live, []byte(rendered)); err != nil {
		t.Fatal(err)
	}
	if askedTag != "v0.1.57" || !strings.Contains(string(fs1[0].Content), "vectis-webmail:v0.1.57@"+dWeb+"\n") ||
		!strings.Contains(string(fs1[0].Content), "vectis-api:v0.1.57"+pinned+"\n") {
		t.Fatalf("tag %q, compose:\n%s", askedTag, fs1[0].Content)
	}

	// Pre-pinning install (no live pins): stays tag-only, no manifest fetch.
	askedTag = ""
	fs2 := files()
	if err := pinNewServices(fs2, []byte("services:\n  api:\n    image: ghcr.io/veltara-works/vectis-api:v0.1.57\n"), []byte(rendered)); err != nil || askedTag != "" || string(fs2[0].Content) != rendered {
		t.Fatalf("unpinned install: err=%v asked=%q", err, askedTag)
	}

	// The manifest doesn't cover the new service, or can't be fetched: refuse.
	manifestDigests = func(string) (map[string]string, error) { return map[string]string{"api": "sha256:x"}, nil }
	if err := pinNewServices(files(), live, []byte(rendered)); err == nil || !strings.Contains(err.Error(), "no digest for webmail") {
		t.Fatalf("missing digest: %v", err)
	}
	manifestDigests = func(string) (map[string]string, error) { return nil, os.ErrDeadlineExceeded }
	if err := pinNewServices(files(), live, []byte(rendered)); err == nil {
		t.Fatal("manifest fetch failure must refuse")
	}
}

// On a partially pinned install, switching webmail on also pins the unchanged
// but tag-only rspamd; re-planning from the final compose must recreate it
// onto that digest too (Copilot, #297).
func TestReplanAfterPinningPartiallyPinnedInstall(t *testing.T) {
	const pinned = "@sha256:e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5e5"
	const dWeb = "sha256:f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6f6"
	const dSpam = "sha256:a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7a7"
	live := []byte("services:\n  api:\n    image: ghcr.io/veltara-works/vectis-api:v0.1.57" + pinned +
		"\n  rspamd:\n    image: ghcr.io/veltara-works/vectis-rspamd:v0.1.57\n")
	rendered := []byte("services:\n  api:\n    image: ghcr.io/veltara-works/vectis-api:v0.1.57" + pinned +
		"\n  rspamd:\n    image: ghcr.io/veltara-works/vectis-rspamd:v0.1.57\n  webmail:\n    image: ghcr.io/veltara-works/vectis-webmail:v0.1.57\n")
	files := []engine.GeneratedFile{{RelPath: composeRelPath, Content: rendered}}

	orig := manifestDigests
	defer func() { manifestDigests = orig }()
	manifestDigests = func(string) (map[string]string, error) {
		return map[string]string{"webmail": dWeb, "rspamd": dSpam}, nil
	}

	before, err := planRecreate(live, rendered, recreatePlan{})
	if err != nil || strings.Join(before.Services, ",") != "webmail" {
		t.Fatalf("initial plan = %+v, %v", before, err)
	}
	// finalRecreatePlan (shared by config diff and apply) pins, then re-plans.
	after, pinErr, err := finalRecreatePlan(files, live, recreatePlan{})
	if err != nil || pinErr != nil {
		t.Fatal(err, pinErr)
	}
	if strings.Join(after.Services, ",") != "rspamd,webmail" {
		t.Fatalf("re-plan = %v, want rspamd (newly pinned) and webmail", after.Services)
	}
	if !strings.Contains(string(renderedCompose(files)), "vectis-rspamd:v0.1.57@"+dSpam+"\n") {
		t.Errorf("rspamd not pinned in the final compose:\n%s", renderedCompose(files))
	}

	// A pinning failure comes back as pinErr, with the pre-pinning plan.
	manifestDigests = func(string) (map[string]string, error) { return nil, os.ErrDeadlineExceeded }
	fresh := []engine.GeneratedFile{{RelPath: composeRelPath, Content: rendered}}
	p, pinErr, err := finalRecreatePlan(fresh, live, recreatePlan{})
	if err != nil || pinErr == nil || strings.Join(p.Services, ",") != "webmail" {
		t.Fatalf("pin failure: plan=%v pinErr=%v err=%v", p.Services, pinErr, err)
	}

	// Nothing to recreate: no manifest fetch at all.
	manifestDigests = func(string) (map[string]string, error) { t.Fatal("unexpected manifest fetch"); return nil, nil }
	same := []engine.GeneratedFile{{RelPath: composeRelPath, Content: live}}
	if p, pinErr, err := finalRecreatePlan(same, live, recreatePlan{}); err != nil || pinErr != nil || !p.empty() {
		t.Fatalf("no-op: plan=%+v pinErr=%v err=%v", p, pinErr, err)
	}
}
