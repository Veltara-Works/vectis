package orchestrator

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// applyHelperPrefix is the container-name prefix SpawnSelfReplaceHelper uses.
const applyHelperPrefix = "vectis-apply-helper-"

// Retention for exited self-replace helpers (#290). The newest successful
// helper is kept so its logs can be read if the last cutover is questioned;
// failed helpers are kept so the failure stays inspectable, but capped so a box
// that failed repeatedly does not accumulate them forever.
const (
	keepSucceededHelpers = 1
	keepFailedHelpers    = 3
)

// ApplyHelperCleanupDelay is how long after orchestrator start-up the helper
// clean-up waits. The helper that started this orchestrator is usually still
// finishing `docker compose up -d` when the new process boots; waiting lets it
// exit, so it is the "newest successful helper" that gets kept.
const ApplyHelperCleanupDelay = 2 * time.Minute

// applyHelper is the subset of `docker inspect` output the clean-up needs.
type applyHelper struct {
	ID       string
	Name     string
	Status   string // created | running | paused | restarting | removing | exited | dead
	ExitCode int
	Created  time.Time
}

// selectHelpersToRemove decides which helpers to remove. It never selects a
// helper that might still be doing work (running, paused, restarting,
// removing). Of the rest, a helper that exited 0 counts as succeeded; one that
// exited non-zero, died, or was created but never started counts as failed.
// The newest keepOK succeeded and keepFailed failed helpers survive.
func selectHelpersToRemove(helpers []applyHelper, keepOK, keepFailed int) []applyHelper {
	var ok, failed []applyHelper
	for _, h := range helpers {
		switch h.Status {
		case "exited":
			if h.ExitCode == 0 {
				ok = append(ok, h)
			} else {
				failed = append(failed, h)
			}
		case "dead", "created":
			failed = append(failed, h)
		}
	}
	newestFirst := func(hs []applyHelper) {
		sort.SliceStable(hs, func(i, j int) bool { return hs[i].Created.After(hs[j].Created) })
	}
	newestFirst(ok)
	newestFirst(failed)

	var remove []applyHelper
	if len(ok) > keepOK {
		remove = append(remove, ok[keepOK:]...)
	}
	if len(failed) > keepFailed {
		remove = append(remove, failed[keepFailed:]...)
	}
	return remove
}

// listApplyHelpers returns every self-replace helper container, in any state.
func (dm *DockerManager) listApplyHelpers(ctx context.Context) ([]applyHelper, error) {
	cmd := exec.CommandContext(ctx, "docker", "ps", "-aq", "--no-trunc", "--filter", "name="+applyHelperPrefix)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker ps: %w", err)
	}
	ids := strings.Fields(stdout.String())
	if len(ids) == 0 {
		return nil, nil
	}

	cmd = exec.CommandContext(ctx, "docker", append([]string{"inspect"}, ids...)...)
	stdout.Reset()
	cmd.Stdout = &stdout
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("docker inspect helpers: %w", err)
	}
	return parseApplyHelpers(stdout.Bytes())
}

// parseApplyHelpers parses `docker inspect` JSON. The name filter on `docker
// ps` is a substring match, so only names that start with the helper prefix
// are returned.
func parseApplyHelpers(data []byte) ([]applyHelper, error) {
	var parsed []struct {
		ID      string `json:"Id"`
		Name    string `json:"Name"`
		Created string `json:"Created"`
		State   struct {
			Status   string `json:"Status"`
			ExitCode int    `json:"ExitCode"`
		} `json:"State"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, fmt.Errorf("parse docker inspect: %w", err)
	}
	out := make([]applyHelper, 0, len(parsed))
	for _, p := range parsed {
		name := strings.TrimPrefix(p.Name, "/")
		if !strings.HasPrefix(name, applyHelperPrefix) {
			continue
		}
		created, err := time.Parse(time.RFC3339Nano, p.Created)
		if err != nil {
			return nil, fmt.Errorf("parse created time of %s: %w", name, err)
		}
		out = append(out, applyHelper{
			ID:       p.ID,
			Name:     name,
			Status:   p.State.Status,
			ExitCode: p.State.ExitCode,
			Created:  created,
		})
	}
	return out, nil
}

// PruneApplyHelpers removes exited self-replace helper containers beyond the
// retention above (#290). Each exited helper pins the old orchestrator image it
// ran from, so without this neither the weekly image GC nor `docker image
// prune` can reclaim those images. Best-effort: a helper that cannot be removed
// is logged and skipped. Returns the names removed.
func (dm *DockerManager) PruneApplyHelpers(ctx context.Context) ([]string, error) {
	helpers, err := dm.listApplyHelpers(ctx)
	if err != nil {
		return nil, err
	}
	var removed []string
	for _, h := range selectHelpersToRemove(helpers, keepSucceededHelpers, keepFailedHelpers) {
		// No -f: a helper that has started running again since the inspect is
		// refused by docker rather than killed.
		cmd := exec.CommandContext(ctx, "docker", "rm", h.ID)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			dm.logger.Warn("apply helper clean-up: remove failed (skipping)",
				"helper_name", h.Name, "error", err, "stderr", strings.TrimSpace(stderr.String()))
			continue
		}
		removed = append(removed, h.Name)
	}
	if len(removed) > 0 {
		dm.logger.Info("apply helper clean-up: removed exited helpers",
			"removed", len(removed), "names", removed, "found", len(helpers))
	}
	return removed, nil
}
