package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Veltara-Works/vectis/internal/engine"
	"github.com/Veltara-Works/vectis/internal/orchestrator"
)

// Applying compose-level changes (#262). `config apply` rewrites the live
// docker-compose.yml, but container environment, healthchecks, resource limits,
// mounts and optional services only take effect when the container is
// recreated. config apply works out which services' compose blocks changed and
// asks the orchestrator to recreate them (POST /internal/recreate), health-gated
// and in dependency order. The orchestrator never recreates itself there; a
// change to its own block needs `vectis update apply`.

// recreatePendingFile records a recreate that was planned but didn't finish
// (orchestrator unreachable, a service unhealthy). The compose file is already
// rewritten by then, so a re-run would see no compose diff; the marker makes it
// retry those services.
const recreatePendingFile = ".config-apply-recreate-pending.json"

// recreatePlan is what config apply will ask the orchestrator to do.
type recreatePlan struct {
	Services []string `json:"services,omitempty"` // changed or added, excluding the orchestrator
	Removed  []string `json:"removed,omitempty"`
	// OrchestratorChanged: the orchestrator's own compose block changed.
	OrchestratorChanged bool `json:"orchestrator_changed,omitempty"`
}

func (p recreatePlan) empty() bool { return len(p.Services) == 0 && len(p.Removed) == 0 }

// recreateOutcome is the recreate part of `config apply --json`.
type recreateOutcome struct {
	Plan   recreatePlan                 `json:"plan"`
	Result *orchestrator.RecreateResult `json:"result,omitempty"`
	Error  string                       `json:"error,omitempty"`
	Backup string                       `json:"compose_backup,omitempty"`
}

// planRecreate compares the live and rendered compose per service and merges
// in a pending recreate left by an earlier run, keeping only what still makes
// sense against the rendered compose.
func planRecreate(live, rendered []byte, pending recreatePlan) (recreatePlan, error) {
	changed, added, removed, err := engine.ComposeServiceChanges(live, rendered)
	if err != nil {
		return recreatePlan{}, err
	}
	_, inRendered, _, err := engine.ComposeServiceChanges(nil, rendered)
	if err != nil {
		return recreatePlan{}, err
	}
	present := map[string]bool{}
	for _, s := range inRendered {
		present[s] = true
	}

	svcs, gone := map[string]bool{}, map[string]bool{}
	var p recreatePlan
	for _, s := range append(append(changed, added...), pending.Services...) {
		if s == "orchestrator" {
			p.OrchestratorChanged = true
			continue
		}
		if present[s] {
			svcs[s] = true
		}
	}
	for _, s := range append(removed, pending.Removed...) {
		if s != "orchestrator" && !present[s] {
			gone[s] = true
		}
	}
	for s := range svcs {
		p.Services = append(p.Services, s)
	}
	for s := range gone {
		p.Removed = append(p.Removed, s)
	}
	sort.Strings(p.Services)
	sort.Strings(p.Removed)
	return p, nil
}

func readRecreatePending(configDir string) (recreatePlan, error) {
	var p recreatePlan
	b, err := os.ReadFile(filepath.Join(configDir, recreatePendingFile))
	if errors.Is(err, fs.ErrNotExist) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if err := json.Unmarshal(b, &p); err != nil {
		return recreatePlan{}, fmt.Errorf("parse %s: %w", recreatePendingFile, err)
	}
	return p, nil
}

// writeRecreatePending writes the marker atomically (temp file, fsync,
// rename), so an interruption leaves the old marker or the new one, never a
// truncated file.
func writeRecreatePending(configDir string, p recreatePlan) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(configDir, recreatePendingFile+".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(configDir, recreatePendingFile))
}

func clearRecreatePending(configDir string) error {
	err := os.Remove(filepath.Join(configDir, recreatePendingFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// backupLiveCompose copies the live compose aside before it is rewritten and
// returns the backup path ("" when there is no live compose).
func backupLiveCompose(configDir string, live []byte, now time.Time) (string, error) {
	if live == nil {
		return "", nil
	}
	path := filepath.Join(configDir, composeRelPath+".pre-config-apply-"+now.UTC().Format("20060102T150405Z"))
	return path, os.WriteFile(path, live, 0o600)
}

// supersedeActions drops the reload/restart for services being recreated: the
// recreate starts them on the new configs anyway.
func supersedeActions(actions []engine.ServiceAction, p recreatePlan) []engine.ServiceAction {
	skip := map[string]bool{}
	for _, s := range append(append([]string(nil), p.Services...), p.Removed...) {
		skip[s] = true
	}
	out := make([]engine.ServiceAction, len(actions))
	for i, a := range actions {
		if skip[a.Service] && a.Action != "none" {
			a.Reason = "superseded by recreate"
			a.Action = "none"
		}
		out[i] = a
	}
	return out
}

// orchReservation is the orchestrator held for this config apply (#262).
type orchReservation struct {
	client   *orchestrator.Client
	id       string
	consumed bool
}

// reserveOrchestrator reserves the orchestrator for this run. It returns nil
// (and no error) when the orchestrator is unreachable: a config apply that
// needs no recreate may still go ahead. A running orchestrator that refuses
// (busy, mid self-update) is an error.
func reserveOrchestrator(cmd *cobra.Command) (*orchReservation, error) {
	client, err := newOrchestratorClient(cmd)
	if err != nil {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	id, err := client.BeginRecreate(ctx)
	if errors.Is(err, orchestrator.ErrOrchestratorUnreachable) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("the orchestrator can't take a config apply now: %w", err)
	}
	return &orchReservation{client: client, id: id}, nil
}

// release hands an unused reservation back. Safe on nil and after use.
func (r *orchReservation) release() {
	if r == nil || r.consumed || r.id == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	_ = r.client.CancelRecreate(ctx, r.id) // on failure it expires on its own
	r.consumed = true
}

// runRecreate asks the orchestrator to carry out the plan, consuming the
// reservation. The caller wrote the pending marker before touching any live
// file; it is cleared here only on full success.
func runRecreate(r *orchReservation, configDir string, p recreatePlan) (*orchestrator.RecreateResult, error) {
	r.consumed = true
	ctx, cancel := context.WithTimeout(context.Background(), orchestrator.RecreateMaxDuration+time.Minute)
	defer cancel()
	res, err := r.client.Recreate(ctx, orchestrator.RecreateRequest{Reservation: r.id, Services: p.Services, Removed: p.Removed})
	if err != nil {
		return nil, err
	}
	if res.Success {
		if err := clearRecreatePending(configDir); err != nil {
			return res, fmt.Errorf("recreate succeeded but %s could not be removed: %w", recreatePendingFile, err)
		}
	}
	return res, nil
}

// printRecreatePlan is shared by config diff and config apply.
func printRecreatePlan(cmd *cobra.Command, p recreatePlan) {
	w := cmd.OutOrStdout()
	if len(p.Removed) > 0 {
		fmt.Fprintf(w, "  remove:   %v\n", p.Removed)
	}
	if len(p.Services) > 0 {
		fmt.Fprintf(w, "  recreate: %v\n", p.Services)
	}
	if p.OrchestratorChanged {
		fmt.Fprintln(w, "  orchestrator: its own settings changed; they take effect on the next `vectis update apply`")
	}
}

// liveAndRenderedCompose returns the live compose (nil if none yet) and the
// rendered one from files (with the live pins already carried over).
func liveAndRenderedCompose(configDir string, files []engine.GeneratedFile) (live, rendered []byte, err error) {
	live, err = os.ReadFile(filepath.Join(configDir, composeRelPath))
	if errors.Is(err, fs.ErrNotExist) {
		live, err = nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("read live compose: %w", err)
	}
	return live, renderedCompose(files), nil
}

// finalRecreatePlan works out the containers config apply recreates. When
// there are any, it first pins newly enabled vectis-* services in files to the
// installed release's signed manifest (pinNewServices), then re-plans from the
// pinned compose: pinning can also pin an unchanged, tag-only service (a
// partially pinned install), which must then be recreated onto its digest
// too. config diff and config apply both use it, so the preview matches apply.
//
// pinErr is a pinning failure (apply refuses; diff warns), returned with the
// plan as it stood before pinning; err is a failure to plan at all.
func finalRecreatePlan(files []engine.GeneratedFile, live []byte, pending recreatePlan) (plan recreatePlan, pinErr, err error) {
	plan, err = planRecreate(live, renderedCompose(files), pending)
	if err != nil || plan.empty() {
		return plan, nil, err
	}
	if pinErr = pinNewServices(files, live, renderedCompose(files)); pinErr != nil {
		return plan, pinErr, nil
	}
	plan, err = planRecreate(live, renderedCompose(files), pending)
	return plan, nil, err
}

// renderedCompose returns the compose among the generated files (nil if none).
func renderedCompose(files []engine.GeneratedFile) []byte {
	var rendered []byte
	for _, f := range files {
		if f.RelPath == composeRelPath {
			rendered = f.Content
		}
	}
	return rendered
}

// printRecreateOutcome reports what config apply recreated.
func printRecreateOutcome(cmd *cobra.Command, o *recreateOutcome) {
	w := cmd.OutOrStdout()
	fmt.Fprintln(w)
	if o.Plan.empty() {
		printRecreatePlan(cmd, o.Plan) // only the orchestrator note
		return
	}
	fmt.Fprintln(w, "Containers (compose-level changes):")
	if o.Result != nil {
		for _, s := range o.Result.Steps {
			status := "OK"
			if !s.Success {
				status = "FAILED: " + s.Error
			}
			fmt.Fprintf(w, "  %s %s (%ds): %s\n", s.Action, s.Service, s.Seconds, status)
		}
		for _, s := range o.Result.Skipped {
			fmt.Fprintf(w, "  %s: not attempted (an earlier step failed)\n", s)
		}
	}
	if o.Plan.OrchestratorChanged {
		fmt.Fprintln(w, "  orchestrator: its own settings changed; they take effect on the next `vectis update apply`")
	}
	if o.Error != "" || (o.Result != nil && !o.Result.Success) {
		if o.Error != "" {
			fmt.Fprintf(w, "  recreate did not run: %s\n", o.Error)
		}
		fmt.Fprintln(w, "  The new settings are written; the containers above are not all running them yet.")
		fmt.Fprintln(w, "  Fix the cause and run `vectis config apply` again: it retries the pending containers.")
		if o.Backup != "" {
			fmt.Fprintf(w, "  The previous docker-compose.yml is saved at %s.\n", o.Backup)
		}
	}
}

// lockConfigApply takes an exclusive, non-blocking lock in the config dir for
// the whole config apply, so a second run can't rewrite the compose or configs
// while the first one's recreate is using them. The lock is released when the
// process exits.
func lockConfigApply(configDir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(configDir, ".config-apply.lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open lock file: %w", err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, fmt.Errorf("another `vectis config apply` is running")
		}
		return nil, fmt.Errorf("lock: %w", err)
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); f.Close() }, nil
}

// manifestDigests returns the image digests a signed release manifest lists
// for tag (verified against the embedded release key).
var manifestDigests = func(tag string) (map[string]string, error) {
	m, _, err := fetchVerifyManifest(verifyEnv{http: &http.Client{Timeout: 30 * time.Second}, baseURL: vectisDownloadBase}, tag)
	if err != nil {
		return nil, err
	}
	return m.Images, nil
}

// pinNewServices pins the vectis-* images that have no digest in the rendered
// compose (services just switched on, so there was no live pin to carry) to
// the digests in the installed release's signed manifest. Only on an install
// whose live compose is pinned: a pre-pinning install stays tag-only. A service
// the manifest doesn't cover is an error, so nothing starts from a mutable tag
// on a pinned install.
func pinNewServices(files []engine.GeneratedFile, live, rendered []byte) error {
	if engine.ComposeImagePinCount(live) == 0 {
		return nil
	}
	unpinned := engine.UnpinnedComposeImages(rendered)
	if len(unpinned) == 0 {
		return nil
	}
	tag := engine.ComposeImageTag(rendered)
	if tag == "" {
		return fmt.Errorf("cannot tell the release tag of the rendered images")
	}
	digests, err := manifestDigests(tag)
	if err != nil {
		return fmt.Errorf("pin %s to the signed %s manifest: %w", strings.Join(unpinned, ", "), tag, err)
	}
	for _, s := range unpinned {
		if digests[s] == "" {
			return fmt.Errorf("the signed %s manifest has no digest for %s", tag, s)
		}
	}
	for i := range files {
		if files[i].RelPath == composeRelPath {
			files[i].Content = engine.PinComposeImages(files[i].Content, digests)
		}
	}
	return nil
}
