package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Veltara-Works/vectis/internal/releasesign"
)

const (
	vDigestAPI    = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	vDigestPostfx = "sha256:2222222222222222222222222222222222222222222222222222222222222222"
	vDigestClam   = "sha256:3333333333333333333333333333333333333333333333333333333333333333"
)

// verifyFixture serves signed manifests from an httptest server and fakes the
// docker + binary side of the box.
type verifyFixture struct {
	t       *testing.T
	priv    ed25519.PrivateKey
	files   map[string][]byte // path → body served with 200; absent → 404
	srv     *httptest.Server
	binPath string
	binSHA  string
	running map[string]containerImage // container → image
}

func newVerifyFixture(t *testing.T) *verifyFixture {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(releasesign.SetSigningKeyForTest(pub))

	f := &verifyFixture{t: t, priv: priv, files: map[string][]byte{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, ok := f.files[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(f.srv.Close)

	f.binPath = filepath.Join(t.TempDir(), "vectis")
	bin := []byte("the published vectis binary")
	if err := os.WriteFile(f.binPath, bin, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(bin)
	f.binSHA = hex.EncodeToString(sum[:])

	f.running = map[string]containerImage{
		"vectis-api":     {Present: true, Ref: "ghcr.io/veltara-works/vectis-api:v0.1.50@" + vDigestAPI, RepoDigests: []string{"ghcr.io/veltara-works/vectis-api@" + vDigestAPI}},
		"vectis-postfix": {Present: true, Ref: "ghcr.io/veltara-works/vectis-postfix:v0.1.50@" + vDigestPostfx, RepoDigests: []string{"ghcr.io/veltara-works/vectis-postfix@" + vDigestPostfx}},
		// vectis-clamav deliberately not deployed (optional profile).
	}
	return f
}

func (f *verifyFixture) manifest(latest, channel string) []byte {
	b, _ := json.Marshal(map[string]any{
		"latest": latest, "released_at": "2026-10-05T00:00:00Z", "channel": channel,
		"binary_sha256": f.binSHA,
		"images":        map[string]string{"api": vDigestAPI, "postfix": vDigestPostfx, "clamav": vDigestClam},
	})
	return b
}

// publish serves body at path with a valid signature at path+".ed25519".
func (f *verifyFixture) publish(path string, body []byte) {
	f.files[path] = body
	f.files[path+".ed25519"] = []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(f.priv, body)))
}

func (f *verifyFixture) env(ver string) verifyEnv {
	return verifyEnv{
		http:    f.srv.Client(),
		baseURL: f.srv.URL,
		version: ver,
		inspect: func(c string) (containerImage, error) {
			return f.running[c], nil // zero value = not present
		},
		binaryPath: func() (string, error) { return f.binPath, nil },
		now:        func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) },
	}
}

func verifyCheckStatus(r *verifyReport, name string) string {
	for _, c := range r.Checks {
		if c.Name == name {
			return c.Status
		}
	}
	return "<missing>"
}

func TestVerify_PerVersionManifestAllMatch(t *testing.T) {
	f := newVerifyFixture(t)
	f.publish("/v0.1.50/release.json", f.manifest("v0.1.50", "stable"))
	r := runVerify(f.env("v0.1.50"))
	if r.Result != verifyResultPass {
		t.Fatalf("want pass, got %s: %+v", r.Result, r.Checks)
	}
	if got := verifyCheckStatus(r, "image clamav"); got != "skip" {
		t.Errorf("undeployed optional service must be skipped, got %s", got)
	}
	if !strings.HasSuffix(r.ManifestSource, "/v0.1.50/release.json") {
		t.Errorf("should prefer the per-version manifest, used %s", r.ManifestSource)
	}
}

func TestVerify_ImageMismatchFails(t *testing.T) {
	f := newVerifyFixture(t)
	f.publish("/v0.1.50/release.json", f.manifest("v0.1.50", "stable"))
	other := "sha256:9999999999999999999999999999999999999999999999999999999999999999"
	f.running["vectis-postfix"] = containerImage{Present: true, Ref: "ghcr.io/veltara-works/vectis-postfix:v0.1.50", RepoDigests: []string{"ghcr.io/veltara-works/vectis-postfix@" + other}}
	r := runVerify(f.env("v0.1.50"))
	if r.Result != verifyResultFail || verifyCheckStatus(r, "image postfix") != "fail" {
		t.Fatalf("a swapped image must fail; got %s %+v", r.Result, r.Checks)
	}
}

func TestVerify_ImageFromAnotherRepoWithSameDigestFails(t *testing.T) {
	f := newVerifyFixture(t)
	f.publish("/v0.1.50/release.json", f.manifest("v0.1.50", "stable"))
	f.running["vectis-api"] = containerImage{Present: true, RepoDigests: []string{"ghcr.io/attacker/vectis-api@" + vDigestAPI}}
	if r := runVerify(f.env("v0.1.50")); verifyCheckStatus(r, "image api") != "fail" {
		t.Fatalf("digest must match the vectis repo, not any repo; got %+v", r.Checks)
	}
}

func TestVerify_BinaryMismatchFails(t *testing.T) {
	f := newVerifyFixture(t)
	f.publish("/v0.1.50/release.json", f.manifest("v0.1.50", "stable"))
	if err := os.WriteFile(f.binPath, []byte("a different binary"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := runVerify(f.env("v0.1.50"))
	if r.Result != verifyResultFail || verifyCheckStatus(r, "binary") != "fail" {
		t.Fatalf("a replaced CLI binary must fail; got %s %+v", r.Result, r.Checks)
	}
}

func TestVerify_FallsBackToChannelManifestNamingThisVersion(t *testing.T) {
	f := newVerifyFixture(t)
	f.publish("/releases-stable.json", f.manifest("v0.1.49", "stable")) // no per-version file (pre-v0.1.50)
	r := runVerify(f.env("v0.1.49"))
	if r.Result != verifyResultPass || !strings.HasSuffix(r.ManifestSource, "/releases-stable.json") {
		t.Fatalf("want pass via channel manifest, got %s from %s: %+v", r.Result, r.ManifestSource, r.Checks)
	}
}

func TestVerify_ChannelMovedOnIsUnverifiableNotFail(t *testing.T) {
	f := newVerifyFixture(t)
	f.publish("/releases-stable.json", f.manifest("v0.1.51", "stable"))
	r := runVerify(f.env("v0.1.49"))
	if r.Result != verifyResultUnverifiable {
		t.Fatalf("a box behind the channel with no per-version manifest is unverifiable, not failed; got %s", r.Result)
	}
}

func TestVerify_RCUsesRCChannel(t *testing.T) {
	f := newVerifyFixture(t)
	f.publish("/releases-rc.json", f.manifest("v0.1.50-rc1", "rc"))
	if r := runVerify(f.env("v0.1.50-rc1")); r.Result != verifyResultPass {
		t.Fatalf("rc box should verify against releases-rc.json; got %s %+v", r.Result, r.Checks)
	}
}

func TestVerify_BadSignatureFails(t *testing.T) {
	f := newVerifyFixture(t)
	f.publish("/v0.1.50/release.json", f.manifest("v0.1.50", "stable"))
	f.files["/v0.1.50/release.json"] = f.manifest("v0.1.50", "stable")               // same shape...
	f.files["/v0.1.50/release.json"] = append(f.files["/v0.1.50/release.json"], ' ') // ...but not the signed bytes
	r := runVerify(f.env("v0.1.50"))
	if r.Result != verifyResultFail || verifyCheckStatus(r, "manifest") != "fail" {
		t.Fatalf("a tampered manifest must fail; got %s %+v", r.Result, r.Checks)
	}
}

func TestVerify_MissingSignatureFails(t *testing.T) {
	f := newVerifyFixture(t)
	f.publish("/v0.1.50/release.json", f.manifest("v0.1.50", "stable"))
	delete(f.files, "/v0.1.50/release.json.ed25519")
	if r := runVerify(f.env("v0.1.50")); r.Result != verifyResultFail {
		t.Fatalf("a published manifest with a stripped signature must fail; got %s", r.Result)
	}
}

func TestVerify_PerVersionManifestNamingAnotherVersionFails(t *testing.T) {
	f := newVerifyFixture(t)
	f.publish("/v0.1.50/release.json", f.manifest("v0.1.49", "stable")) // validly signed, wrong version
	if r := runVerify(f.env("v0.1.50")); r.Result != verifyResultFail {
		t.Fatalf("a replayed manifest at another version's path must fail; got %s", r.Result)
	}
}

func TestVerify_DevBuildUnverifiable(t *testing.T) {
	f := newVerifyFixture(t)
	if r := runVerify(f.env("dev")); r.Result != verifyResultUnverifiable {
		t.Fatalf("dev build must be unverifiable; got %s", r.Result)
	}
}

func TestVerify_OfflineUnverifiable(t *testing.T) {
	f := newVerifyFixture(t)
	env := f.env("v0.1.50")
	f.srv.Close()
	if r := runVerify(env); r.Result != verifyResultUnverifiable {
		t.Fatalf("network failure must be unverifiable, never fail; got %s", r.Result)
	}
}

func TestVerify_InspectErrorIsUnverifiable(t *testing.T) {
	f := newVerifyFixture(t)
	f.publish("/v0.1.50/release.json", f.manifest("v0.1.50", "stable"))
	env := f.env("v0.1.50")
	env.inspect = func(string) (containerImage, error) { return containerImage{}, errors.New("docker unavailable") }
	if r := runVerify(env); r.Result != verifyResultUnverifiable {
		t.Fatalf("docker errors must be unverifiable; got %s", r.Result)
	}
}

func TestVerifyDue(t *testing.T) {
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	pass := func(age time.Duration) *verifyReport {
		return &verifyReport{Result: verifyResultPass, CheckedAt: now.Add(-age)}
	}
	cases := []struct {
		name     string
		deployed time.Time
		last     *verifyReport
		want     bool
	}{
		{"recent deploy, checked 1h ago → still due (timer paces 6h)", now.Add(-10 * time.Hour), pass(time.Hour), true},
		{"old deploy, clean pass 3h ago → not due", now.Add(-72 * time.Hour), pass(3 * time.Hour), false},
		{"old deploy, clean pass 25h ago → due", now.Add(-72 * time.Hour), pass(25 * time.Hour), true},
		{"old deploy, last result failed → due", now.Add(-72 * time.Hour), &verifyReport{Result: verifyResultFail, CheckedAt: now.Add(-time.Hour)}, true},
		{"no record → due", now.Add(-72 * time.Hour), nil, true},
		{"unknown deploy time, clean pass 3h ago → not due", time.Time{}, pass(3 * time.Hour), false},
	}
	for _, c := range cases {
		if got, why := verifyDue(now, c.deployed, c.last); got != c.want {
			t.Errorf("%s: got %v (%s), want %v", c.name, got, why, c.want)
		}
	}
}

func TestVerifyAlert(t *testing.T) {
	fail := &verifyReport{Version: "v0.1.50", Result: verifyResultFail, Checks: []verifyCheck{{Name: "binary", Status: "fail", Detail: "x"}}}
	pass := &verifyReport{Version: "v0.1.50", Result: verifyResultPass}
	unv := &verifyReport{Version: "v0.1.50", Result: verifyResultUnverifiable}

	if subj, body, send := verifyAlert(fail, pass, "mail"); !send || !strings.Contains(subj, "FAIL") || !strings.Contains(body, "security alert") {
		t.Errorf("a FAIL must alert with a security-alert body; got send=%v subj=%q", send, subj)
	}
	if _, _, send := verifyAlert(pass, pass, "mail"); send {
		t.Error("a clean pass must be log-only (Ian, 2026-10-04)")
	}
	if _, _, send := verifyAlert(unv, pass, "mail"); send {
		t.Error("unverifiable (e.g. offline) must not email")
	}
	if subj, _, send := verifyAlert(pass, fail, "mail"); !send || !strings.Contains(subj, "recovered") {
		t.Errorf("first pass after a FAIL must send one recovery email; got send=%v subj=%q", send, subj)
	}
	if _, _, send := verifyAlert(pass, nil, "mail"); send {
		t.Error("a first-ever pass must not email")
	}
}

func TestVerifyUnits(t *testing.T) {
	svc, tmr := verifyUnits("/usr/local/bin/vectis", "ops@example.com", "vectis-verify@example.com")
	if !strings.Contains(svc, "ExecStart=/usr/local/bin/vectis verify --scheduled --alert-to ops@example.com --alert-from vectis-verify@example.com") {
		t.Errorf("service ExecStart wrong:\n%s", svc)
	}
	if !strings.Contains(svc, "SuccessExitStatus=2") {
		t.Error("unverifiable (exit 2) must not mark the unit failed")
	}
	for _, want := range []string{"OnUnitActiveSec=6h", "OnBootSec=15min", "Persistent=true", "WantedBy=timers.target"} {
		if !strings.Contains(tmr, want) {
			t.Errorf("timer missing %q:\n%s", want, tmr)
		}
	}
	if svc, _ := verifyUnits("/usr/local/bin/vectis", "", ""); !strings.Contains(svc, "ExecStart=/usr/local/bin/vectis verify --scheduled\n") {
		t.Errorf("no alert flags without --alert-to:\n%s", svc)
	}
}

func TestEmailLike(t *testing.T) {
	for _, ok := range []string{"ianholt@afxgroup.com.au", "vectis-verify@vectismail.com"} {
		if !emailLike.MatchString(ok) {
			t.Errorf("%q should be accepted", ok)
		}
	}
	for _, bad := range []string{"", "no-at-sign", "a b@example.com", "x@y; rm -rf /", `"q"@x.com`} {
		if emailLike.MatchString(bad) {
			t.Errorf("%q must be rejected (it is written into a unit file)", bad)
		}
	}
}
