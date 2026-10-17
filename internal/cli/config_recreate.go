package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
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

func writeRecreatePending(configDir string, p recreatePlan) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(configDir, recreatePendingFile), b, 0o600)
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

// runRecreate asks the orchestrator to carry out the plan. The pending marker
// is written first and cleared only on full success.
func runRecreate(cmd *cobra.Command, configDir string, p recreatePlan) (*orchestrator.RecreateResult, error) {
	if err := writeRecreatePending(configDir, p); err != nil {
		return nil, fmt.Errorf("record pending recreate: %w", err)
	}
	client, err := newOrchestratorClient(cmd)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), orchestrator.RecreateMaxDuration+time.Minute)
	defer cancel()
	res, err := client.Recreate(ctx, orchestrator.RecreateRequest{Services: p.Services, Removed: p.Removed})
	if err != nil {
		return nil, err
	}
	if res.Success {
		if err := clearRecreatePending(configDir); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "Warning: could not remove %s: %s\n", recreatePendingFile, err)
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
	for _, f := range files {
		if f.RelPath == composeRelPath {
			rendered = f.Content
		}
	}
	return live, rendered, nil
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
