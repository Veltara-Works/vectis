package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/orchestrator"
	"github.com/Veltara-Works/vectis/internal/releasesign"
	"github.com/Veltara-Works/vectis/internal/version"
)

// --- vectis verify ---
//
// Checks that THIS box runs exactly what was published for its version: the
// signed release manifest for the running version, every deployed service's
// image (by registry digest), and the installed CLI binary (by sha256). It
// automates the manual verification battery done by hand at each release
// (supply-chain guarantee; see docs/notes/vectis-verify-design-2026-10-04.md
// in the private notes).
//
// Exit codes: 0 = every check passed; 1 = a check FAILED (the box does not run
// what was published, or a manifest/signature didn't verify: treat as a
// security alert); 2 = UNVERIFIABLE (network down, dev build, or no signed
// manifest names the running version). A 2 is never a tamper signal.

const (
	verifyResultPass         = "pass"
	verifyResultFail         = "fail"
	verifyResultUnverifiable = "unverifiable"

	// verifyStatePath lives in its own directory because that directory is
	// bind-mounted read-only into the api container, which shows the result
	// on the admin dashboard. A directory mount, not a file mount: the state
	// is replaced by rename, which a single-file bind mount would not follow.
	// Keep in sync with api.defaultVerifyStatePath.
	verifyStatePath = "/var/lib/vectis/verify/last.json"
	// legacyVerifyStatePath is where v0.1.50 and v0.1.51 recorded the result.
	// Read once as a fallback so an open failure keeps its failing_since.
	legacyVerifyStatePath = "/var/lib/vectis/verify-last.json"

	// Scheduling (Ian, 2026-10-04): every 6h for the first 48h after a deploy,
	// then daily. The systemd timer fires every 6h; --scheduled decides whether
	// a run is due.
	verifyRecentDeployWindow = 48 * time.Hour
	verifySteadyInterval     = 24 * time.Hour
)

var imageDigestFormat = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// optionalServices are the manifest-pinned services the compose template only
// renders when enabled (webmail, a ClamAV profile, Let's Encrypt TLS). Every
// other pinned service must be running: a missing core container is a FAIL,
// and a service added to the manifest later is required unless listed here.
var optionalServices = map[string]bool{"webmail": true, "clamav": true, "cert-extractor": true}

type verifyCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"` // pass | fail | skip | unknown
	Detail string `json:"detail,omitempty"`
}

type verifyReport struct {
	Version        string        `json:"version"`
	ManifestSource string        `json:"manifest_source,omitempty"`
	Result         string        `json:"result"`
	CheckedAt      time.Time     `json:"checked_at"`
	Checks         []verifyCheck `json:"checks"`
	// FailingSince is when the current unresolved FAIL began. It is carried
	// through unverifiable runs and cleared only by a clean pass, so
	// FAIL → unverifiable → PASS still sends the recovery email.
	FailingSince *time.Time `json:"failing_since,omitempty"`
}

func (r *verifyReport) add(name, status, detail string) {
	r.Checks = append(r.Checks, verifyCheck{Name: name, Status: status, Detail: detail})
}

// containerImage is what verify needs to know about one service's container.
type containerImage struct {
	Present     bool
	Ref         string   // Config.Image, e.g. ghcr.io/veltara-works/vectis-api:v0.1.49@sha256:…
	RepoDigests []string // repo@sha256:… entries of the image the container runs
}

// verifyEnv isolates verify's side effects so the logic is testable.
type verifyEnv struct {
	http       *http.Client
	baseURL    string
	version    string
	inspect    func(container string) (containerImage, error)
	binaryPath func() (string, error)
	now        func() time.Time
	lastDeploy func() (time.Time, error)
	statePath  string
	readState  func(path string) (*verifyReport, error)
	writeState func(path string, r *verifyReport) error
}

// errVerifyUnverifiable marks a failure to establish what SHOULD be running
// (as opposed to proof that something else IS running).
var errVerifyUnverifiable = errors.New("unverifiable")

// fetchVerifyManifest returns the signed manifest for exactly `ver`.
//
// Preferred source: the per-version manifest <base>/<ver>/release.json (+.ed25519),
// published by release CI from v0.1.50. Fallback for older releases: the
// channel manifest, accepted ONLY when it names `ver` itself; if the channel
// has moved on, the box cannot be verified (errVerifyUnverifiable), which is
// deliberately not a failure.
func fetchVerifyManifest(env verifyEnv, ver string) (*orchestrator.ReleaseManifest, string, error) {
	perVersion := env.baseURL + "/" + ver + "/release.json"
	m, err := fetchSignedManifest(env.http, perVersion)
	if err == nil {
		if m.Latest != ver {
			return nil, perVersion, fmt.Errorf("%w: per-version manifest at %s names %q, not %q (replayed or misplaced manifest)", errReleaseVerification, perVersion, m.Latest, ver)
		}
		return m, perVersion, nil
	}
	if !errors.Is(err, errManifestNotFound) {
		return nil, perVersion, err
	}

	channel := orchestrator.ChannelStable
	if strings.Contains(ver, "-rc") {
		channel = orchestrator.ChannelRC
	}
	channelURL := env.baseURL + "/releases-" + channel + ".json"
	m, err = fetchSignedManifest(env.http, channelURL)
	if err != nil {
		if errors.Is(err, errManifestNotFound) {
			return nil, channelURL, fmt.Errorf("%w: no manifest at %s", errVerifyUnverifiable, channelURL)
		}
		return nil, channelURL, err
	}
	if m.Channel != channel {
		return nil, channelURL, fmt.Errorf("%w: %s declares channel %q, want %q", errReleaseVerification, channelURL, m.Channel, channel)
	}
	if m.Latest != ver {
		return nil, channelURL, fmt.Errorf("%w: this box runs %s but the %s channel now publishes %s, and %s has no per-version manifest (published from v0.1.50 onwards); update to the latest release to verify", errVerifyUnverifiable, ver, channel, m.Latest, ver)
	}
	return m, channelURL, nil
}

var errManifestNotFound = errors.New("manifest not found")

// fetchSignedManifest GETs a manifest and its .ed25519 signature and verifies
// the signature BEFORE decoding. Transport problems and non-404 errors (429,
// 5xx, ...) are unverifiable; a missing (404) or bad signature on a manifest
// that IS present is a verification failure.
func fetchSignedManifest(client *http.Client, url string) (*orchestrator.ReleaseManifest, error) {
	body, status, err := httpGetStatus(client, url, 64*1024)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch %s: %v", errVerifyUnverifiable, url, err)
	}
	if status == http.StatusNotFound {
		return nil, errManifestNotFound
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%w: fetch %s: HTTP %d", errVerifyUnverifiable, url, status)
	}
	sig, sigStatus, err := httpGetStatus(client, url+".ed25519", 4*1024)
	if err != nil {
		return nil, fmt.Errorf("%w: fetch %s.ed25519: %v", errVerifyUnverifiable, url, err)
	}
	if sigStatus == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %s is published but its signature is missing (HTTP 404)", errReleaseVerification, url)
	}
	if sigStatus != http.StatusOK {
		return nil, fmt.Errorf("%w: fetch %s.ed25519: HTTP %d", errVerifyUnverifiable, url, sigStatus)
	}
	if err := releasesign.Verify(body, string(sig)); err != nil {
		if errors.Is(err, releasesign.ErrNotConfigured) {
			return nil, fmt.Errorf("%w: %v", errVerifyUnverifiable, err)
		}
		return nil, fmt.Errorf("%w: %s: %v", errReleaseVerification, url, err)
	}
	var m orchestrator.ReleaseManifest
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, fmt.Errorf("%w: decode %s: %v", errReleaseVerification, url, err)
	}
	if !orchestrator.ValidReleaseTag(m.Latest) {
		return nil, fmt.Errorf("%w: %s `latest` = %q is not a valid release tag", errReleaseVerification, url, m.Latest)
	}
	return &m, nil
}

// httpGetStatus is httpGetBody that also reports the status code, so a 404
// (not published) can be told apart from other non-200 responses.
func httpGetStatus(client *http.Client, url string, limit int64) ([]byte, int, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return b, resp.StatusCode, err
}

// runVerify performs every check and returns the report. It never returns an
// error: problems are recorded as checks and reflected in Result.
func runVerify(env verifyEnv) *verifyReport {
	r := &verifyReport{Version: env.version, CheckedAt: env.now().UTC()}
	fail, unverifiable := false, false

	if !orchestrator.ValidReleaseTag(env.version) {
		r.add("version", "unknown", fmt.Sprintf("this CLI reports %q, which is not a release version (dev build?)", env.version))
		r.Result = verifyResultUnverifiable
		return r
	}

	m, src, err := fetchVerifyManifest(env, env.version)
	r.ManifestSource = src
	switch {
	case err == nil:
		r.add("manifest", "pass", fmt.Sprintf("signed manifest for %s verified (Ed25519) from %s", env.version, src))
	case errors.Is(err, errReleaseVerification):
		r.add("manifest", "fail", err.Error())
		r.Result = verifyResultFail
		return r
	default:
		r.add("manifest", "unknown", err.Error())
		r.Result = verifyResultUnverifiable
		return r
	}

	// Images: every service the manifest pins that is deployed on this box.
	if len(m.Images) == 0 {
		r.add("images", "unknown", "manifest pins no image digests (pre-REL-3 release); images not verifiable")
		unverifiable = true
	}
	services := make([]string, 0, len(m.Images))
	for svc := range m.Images {
		services = append(services, svc)
	}
	sort.Strings(services)
	for _, svc := range services {
		want := m.Images[svc]
		name := "image " + svc
		if !imageDigestFormat.MatchString(want) {
			r.add(name, "fail", fmt.Sprintf("manifest digest %q is malformed", want))
			fail = true
			continue
		}
		ci, err := env.inspect("vectis-" + svc)
		if err != nil {
			r.add(name, "unknown", fmt.Sprintf("could not inspect vectis-%s: %v", svc, err))
			unverifiable = true
			continue
		}
		if !ci.Present {
			if optionalServices[svc] {
				r.add(name, "skip", "not deployed on this box")
			} else {
				r.add(name, "fail", fmt.Sprintf("vectis-%s is missing: it is a core service, so every box must run it", svc))
				fail = true
			}
			continue
		}
		repo := "ghcr.io/veltara-works/vectis-" + svc + "@"
		matched := false
		for _, rd := range ci.RepoDigests {
			if strings.EqualFold(rd, repo+want) {
				matched = true
				break
			}
		}
		if matched {
			r.add(name, "pass", want)
		} else {
			r.add(name, "fail", fmt.Sprintf("running image (%s, registry digests %v) is not the published %s", ci.Ref, ci.RepoDigests, want))
			fail = true
		}
	}

	// The installed CLI binary.
	switch {
	case m.BinarySHA256 == "":
		r.add("binary", "unknown", "manifest has no binary_sha256 (pre-REL-1 release)")
		unverifiable = true
	case !orchestrator.ValidBinaryDigest(m.BinarySHA256):
		r.add("binary", "fail", fmt.Sprintf("manifest binary_sha256 %q is malformed", m.BinarySHA256))
		fail = true
	default:
		path, err := env.binaryPath()
		var sum string
		if err == nil {
			sum, err = fileSHA256(path)
		}
		switch {
		case err != nil:
			r.add("binary", "unknown", fmt.Sprintf("could not hash the installed CLI: %v", err))
			unverifiable = true
		case sum == m.BinarySHA256:
			r.add("binary", "pass", fmt.Sprintf("%s sha256 %s", path, sum))
		default:
			r.add("binary", "fail", fmt.Sprintf("%s sha256 %s is not the published %s", path, sum, m.BinarySHA256))
			fail = true
		}
	}

	switch {
	case fail:
		r.Result = verifyResultFail
	case unverifiable:
		r.Result = verifyResultUnverifiable
	default:
		r.Result = verifyResultPass
	}
	return r
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// verifyDue implements the --scheduled cadence: always run within 48h of the
// last deploy (the timer fires every 6h), otherwise run when the last clean
// pass is 24h or more old. Any non-pass last result (or no record) means run.
func verifyDue(now, lastDeploy time.Time, last *verifyReport) (bool, string) {
	if !lastDeploy.IsZero() && now.Sub(lastDeploy) < verifyRecentDeployWindow {
		return true, fmt.Sprintf("deployed %s ago (< 48h): 6-hourly checks", now.Sub(lastDeploy).Round(time.Minute))
	}
	if last == nil {
		return true, "no previous result recorded"
	}
	if last.Result != verifyResultPass {
		return true, fmt.Sprintf("previous result was %q", last.Result)
	}
	if age := now.Sub(last.CheckedAt); age < verifySteadyInterval {
		return false, fmt.Sprintf("last clean pass %s ago (< 24h); not due", age.Round(time.Minute))
	}
	return true, "last clean pass is 24h or more old"
}

// --- docker / filesystem plumbing ---

func dockerContainerImage(container string) (containerImage, error) {
	out, err := exec.Command("docker", "inspect", "--format", "{{.Image}}|{{.Config.Image}}", container).Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && strings.Contains(string(ee.Stderr), "No such") {
			return containerImage{}, nil
		}
		return containerImage{}, err
	}
	id, ref, _ := strings.Cut(strings.TrimSpace(string(out)), "|")
	raw, err := exec.Command("docker", "image", "inspect", "--format", "{{json .RepoDigests}}", id).Output()
	if err != nil {
		return containerImage{}, fmt.Errorf("image inspect %s: %w", id, err)
	}
	var rds []string
	if err := json.Unmarshal(raw, &rds); err != nil {
		return containerImage{}, fmt.Errorf("decode RepoDigests: %w", err)
	}
	return containerImage{Present: true, Ref: ref, RepoDigests: rds}, nil
}

// lastDeployTime uses the api container's creation time: every deploy (update
// apply, canary, config apply) recreates it, so it marks when the running
// release was put in place.
func lastDeployTime() (time.Time, error) {
	out, err := dockerInspect("vectis-api", "{{.Created}}")
	if err != nil {
		return time.Time{}, err
	}
	return time.Parse(time.RFC3339Nano, out)
}

// installedBinaryPath is the CLI the box actually runs: the installed
// /usr/local/bin/vectis (what `update apply` refreshes and the timer invokes),
// falling back to this process's own executable on non-standard installs.
func installedBinaryPath() (string, error) {
	if _, err := os.Stat(expectedBinaryPath); err == nil {
		return filepath.EvalSymlinks(expectedBinaryPath)
	}
	p, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.EvalSymlinks(p)
}

func readVerifyState(path string) (*verifyReport, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var r verifyReport
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// loadPrevVerifyState reads the previous result, falling back once to the
// pre-v0.1.52 location when the default path has no record yet, so an
// unresolved failure keeps its failing_since across the move.
func loadPrevVerifyState(read func(string) (*verifyReport, error), statePath string) *verifyReport {
	prev, _ := read(statePath)
	if prev == nil && statePath == verifyStatePath {
		prev, _ = read(legacyVerifyStatePath)
	}
	return prev
}

func writeVerifyState(path string, r *verifyReport) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(b, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// --- alerting ---

// failingSince reports when prev's unresolved failure began, or nil. A record
// written before FailingSince existed counts as failing if its result was FAIL.
func failingSince(prev *verifyReport) *time.Time {
	switch {
	case prev == nil:
		return nil
	case prev.FailingSince != nil:
		return prev.FailingSince
	case prev.Result == verifyResultFail:
		t := prev.CheckedAt
		return &t
	}
	return nil
}

// carryFailState sets r.FailingSince from this run and the previous record. A
// FAIL keeps the earliest unresolved failure time; an unverifiable run proves
// nothing either way, so it carries the marker forward; a pass clears it.
func carryFailState(r, prev *verifyReport) {
	since := failingSince(prev)
	switch r.Result {
	case verifyResultFail:
		if since == nil {
			t := r.CheckedAt
			since = &t
		}
		r.FailingSince = since
	case verifyResultUnverifiable:
		r.FailingSince = since
	default:
		r.FailingSince = nil
	}
}

// verifyAlert decides whether this run warrants an email and composes it.
// Email goes out on a FAIL, and once on recovery (first pass after a fail,
// even with unverifiable runs in between); a clean pass or an unverifiable
// run is log-only (Ian, 2026-10-04).
func verifyAlert(r, prev *verifyReport, host string) (subject, body string, send bool) {
	since := failingSince(prev)
	switch {
	case r.Result == verifyResultFail:
		subject = fmt.Sprintf("[vectis verify] FAIL on %s: box does not match published %s", host, r.Version)
		if r.FailingSince != nil {
			since = r.FailingSince
		}
	case r.Result == verifyResultPass && since != nil:
		subject = fmt.Sprintf("[vectis verify] recovered on %s: matches published %s again", host, r.Version)
	default:
		return "", "", false
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Host: %s\nVersion: %s\nResult: %s\nChecked: %s\nManifest: %s\n", host, r.Version, strings.ToUpper(r.Result), r.CheckedAt.Format(time.RFC3339), r.ManifestSource)
	if since != nil {
		fmt.Fprintf(&b, "Failing since: %s\n", since.Format(time.RFC3339))
	}
	b.WriteString("\n")
	printVerifyReport(&b, r)
	if r.Result == verifyResultFail {
		b.WriteString("\nA FAIL means a running image or the installed vectis binary is not what was\npublished for this version, or the release manifest/signature did not verify.\nTreat it as a security alert: re-run `vectis verify` and investigate before\nanything else.\n")
	}
	return subject, b.String(), true
}

// sendVerifyAlert hands the message to the stack's own Postfix, the same path
// the container watchdog uses.
func sendVerifyAlert(from, to, subject, body string) error {
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nDate: %s\r\nAuto-Submitted: auto-generated\r\n\r\n%s",
		from, to, subject, time.Now().UTC().Format(time.RFC1123Z), strings.ReplaceAll(body, "\n", "\r\n"))
	cmd := exec.Command("docker", "exec", "-i", "vectis-postfix", "sendmail", "-f", from, to)
	cmd.Stdin = strings.NewReader(msg)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("sendmail via vectis-postfix: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// --- systemd timer ---

const (
	verifyServicePath = "/etc/systemd/system/vectis-verify.service"
	verifyTimerPath   = "/etc/systemd/system/vectis-verify.timer"
)

// emailLike accepts a plain address only: no whitespace (so no CR/LF header
// injection), no quoting, and no leading "-" that sendmail would parse as an
// option.
var emailLike = regexp.MustCompile(`^[^\s@"'\\-][^\s@"'\\]*@[^\s@"'\\]+$`)

// validateAlertAddrs checks --alert-to/--alert-from before they reach a unit
// file, a mail header or sendmail's argv. Both `verify` and `install-timer`
// call it.
func validateAlertAddrs(alertTo, alertFrom string) error {
	for _, a := range []string{alertTo, alertFrom} {
		if a != "" && !emailLike.MatchString(a) {
			return fmt.Errorf("%q is not a plain email address", a)
		}
	}
	if alertTo != "" && alertFrom == "" {
		return fmt.Errorf("--alert-from is required with --alert-to (use an address your mail domain is allowed to send as)")
	}
	return nil
}

// verifyUnits renders the systemd service + timer. The timer fires every 6h
// (and 15 min after boot); `--scheduled` decides whether a run is actually due.
func verifyUnits(binary, alertTo, alertFrom string) (service, timer string) {
	args := "verify --scheduled"
	if alertTo != "" {
		args += " --alert-to " + alertTo
		if alertFrom != "" {
			args += " --alert-from " + alertFrom
		}
	}
	service = fmt.Sprintf(`[Unit]
Description=Vectis Mail: verify the running stack matches its signed release
After=docker.service
Wants=docker.service

[Service]
Type=oneshot
ExecStart=%s %s
# Exit 1 = FAIL (security alert), 2 = unverifiable (e.g. offline). Both are
# recorded in the journal; only a FAIL emails --alert-to.
SuccessExitStatus=2
`, binary, args)
	timer = `[Unit]
Description=Vectis Mail: run vectis verify (6h for 48h after a deploy, then daily)

[Timer]
OnBootSec=15min
OnUnitActiveSec=6h
RandomizedDelaySec=10min
Persistent=true

[Install]
WantedBy=timers.target
`
	return service, timer
}

var verifyInstallTimerCmd = &cobra.Command{
	Use:   "install-timer",
	Short: "Install and enable the vectis-verify systemd timer (requires root)",
	RunE: func(cmd *cobra.Command, _ []string) error {
		alertTo, _ := cmd.Flags().GetString("alert-to")
		alertFrom, _ := cmd.Flags().GetString("alert-from")
		if err := validateAlertAddrs(alertTo, alertFrom); err != nil {
			return err
		}
		svc, tmr := verifyUnits(expectedBinaryPath, alertTo, alertFrom)
		if err := os.WriteFile(verifyServicePath, []byte(svc), 0o644); err != nil {
			return fmt.Errorf("write %s (run as root): %w", verifyServicePath, err)
		}
		if err := os.WriteFile(verifyTimerPath, []byte(tmr), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", verifyTimerPath, err)
		}
		for _, args := range [][]string{{"daemon-reload"}, {"enable", "--now", "vectis-verify.timer"}} {
			if out, err := exec.Command("systemctl", args...).CombinedOutput(); err != nil {
				return fmt.Errorf("systemctl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
			}
		}
		fmt.Fprintf(cmd.OutOrStdout(), "installed %s + %s and enabled vectis-verify.timer\n", verifyServicePath, verifyTimerPath)
		return nil
	},
}

// --- command ---

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify this box runs exactly what was published for its version",
	Long: `Checks the running system against the signed release manifest for its version:
  - the manifest's Ed25519 signature,
  - every deployed service image, by registry digest,
  - the installed vectis CLI binary, by sha256.

Exit codes: 0 all checks passed · 1 a check FAILED (treat as a security alert)
· 2 unverifiable (e.g. offline, or no signed manifest names this version).

--scheduled is for the systemd timer: it runs every 6h for 48h after a deploy,
then once a day, and records each result in ` + verifyStatePath + `.`,
	RunE: runVerifyCmd,
}

func runVerifyCmd(cmd *cobra.Command, _ []string) error {
	jsonOutput, _ := cmd.Flags().GetBool("json")
	scheduled, _ := cmd.Flags().GetBool("scheduled")
	statePath, _ := cmd.Flags().GetString("state-file")
	alertTo, _ := cmd.Flags().GetString("alert-to")
	alertFrom, _ := cmd.Flags().GetString("alert-from")
	if err := validateAlertAddrs(alertTo, alertFrom); err != nil {
		return err
	}

	env := verifyEnv{
		http:       &http.Client{Timeout: 30 * time.Second},
		baseURL:    vectisDownloadBase,
		version:    version.Version,
		inspect:    dockerContainerImage,
		binaryPath: installedBinaryPath,
		now:        time.Now,
		lastDeploy: lastDeployTime,
		statePath:  statePath,
		readState:  readVerifyState,
		writeState: writeVerifyState,
	}
	out := cmd.OutOrStdout()

	prev := loadPrevVerifyState(env.readState, statePath) // missing/unreadable → nil

	if scheduled {
		last := prev
		deployed, _ := env.lastDeploy() // unknown → zero → steady cadence
		due, why := verifyDue(env.now(), deployed, last)
		if !due {
			fmt.Fprintf(out, "vectis verify: skipped (%s)\n", why)
			return nil
		}
	}

	r := runVerify(env)
	carryFailState(r, prev)

	if err := env.writeState(statePath, r); err != nil {
		if scheduled {
			fmt.Fprintf(cmd.ErrOrStderr(), "warning: could not record result in %s: %v\n", statePath, err)
		}
	} else if statePath == verifyStatePath {
		_ = os.Remove(legacyVerifyStatePath) // migrated; best-effort
	}

	if alertTo != "" {
		host, _ := os.Hostname()
		if subject, body, send := verifyAlert(r, prev, host); send {
			if err := sendVerifyAlert(alertFrom, alertTo, subject, body); err != nil {
				fmt.Fprintf(cmd.ErrOrStderr(), "warning: alert email failed: %v\n", err)
			}
		}
	}

	if jsonOutput {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	} else {
		printVerifyReport(out, r)
	}

	switch r.Result {
	case verifyResultFail:
		os.Exit(1)
	case verifyResultUnverifiable:
		os.Exit(2)
	}
	return nil
}

func printVerifyReport(w io.Writer, r *verifyReport) {
	marks := map[string]string{"pass": "PASS", "fail": "FAIL", "skip": "skip", "unknown": "????"}
	for _, c := range r.Checks {
		fmt.Fprintf(w, "  [%s] %-22s %s\n", marks[c.Status], c.Name, c.Detail)
	}
	switch r.Result {
	case verifyResultPass:
		fmt.Fprintf(w, "vectis verify: PASS: this box runs exactly what was published for %s\n", r.Version)
	case verifyResultFail:
		fmt.Fprintf(w, "vectis verify: FAIL: this box does NOT match what was published for %s. Investigate now.\n", r.Version)
	default:
		fmt.Fprintf(w, "vectis verify: UNVERIFIABLE: could not establish what %s should be running (not a tamper signal)\n", r.Version)
	}
}

func init() {
	verifyCmd.Flags().Bool("json", false, "Output the report as JSON")
	verifyCmd.Flags().Bool("scheduled", false, "Timer mode: run only when due (6h for 48h after a deploy, then daily)")
	verifyCmd.Flags().String("state-file", verifyStatePath, "Where to record the last result")
	verifyCmd.Flags().String("alert-to", "", "Email this address on a FAIL (and once on recovery)")
	verifyCmd.Flags().String("alert-from", "", "Sender address for alerts (must be allowed to send from this box)")
	verifyInstallTimerCmd.Flags().String("alert-to", "", "Email this address on a FAIL (and once on recovery)")
	verifyInstallTimerCmd.Flags().String("alert-from", "", "Sender address for alerts")
	verifyCmd.AddCommand(verifyInstallTimerCmd)
	RootCmd.AddCommand(verifyCmd)
}
