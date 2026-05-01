package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/valkey-io/valkey-go"
)

// lastSeenVersionKey is the Valkey key carrying the orchestrator binary
// version observed on the previous startup. Used by
// SelfHealComposeOnVersionTransition to detect cross-version Apply jumps
// where Phase 3.5 ran under the OLD orchestrator's templates and the NEW
// orchestrator (now alive post-Phase-7) needs to reconcile any structural
// drift between on-disk compose and its embedded templates.
const lastSeenVersionKey = "orchestrator:last_seen_version"

// selfHealAction captures the decision for what the orchestrator should
// do given the prior + current version observations. Extracted as its own
// type so the decision logic can be unit tested without spinning up
// Valkey/Docker.
type selfHealAction int

const (
	selfHealSkip      selfHealAction = iota // do nothing (dev build, missing wiring, steady-state)
	selfHealReconcile                       // empty prev OR transition — regen + apply (no-op if no drift)
)

// decideSelfHealAction returns what SelfHealComposeOnVersionTransition
// should do given the inputs. Pure function — no I/O — so it's exhaustively
// unit testable.
//
// prev is the value read from Valkey (empty when key absent). current is
// the running binary's version.Version. The remaining flags capture the
// "is the orchestrator wired enough to do anything" preconditions.
//
// Empty prev is treated as reconcile (not "fresh install — skip"), because
// the upgrade path that motivated self-heal in the first place produces
// exactly this state: the OLD orchestrator (v0.1.0) never wrote the
// last-seen-version key, so the NEW orchestrator (v0.1.3) sees prev=""
// after Phase 7's swap. RegenerateCompose is no-op-on-match, so a
// genuinely fresh install (where on-disk compose was just rendered from
// current templates) safely round-trips through reconcile without
// recreating any containers.
func decideSelfHealAction(prev, current string, hasComposeGen, hasComposePath bool) selfHealAction {
	if current == "" || current == "dev" {
		return selfHealSkip
	}
	if !hasComposeGen || !hasComposePath {
		return selfHealSkip
	}
	if prev == current {
		return selfHealSkip
	}
	return selfHealReconcile
}

// SelfHealComposeOnVersionTransition closes the cross-version gap left by
// §10's Phase-3.5 regen design.
//
// Phase 3.5 of Apply runs in the OLD orchestrator's process (the new image
// hasn't swapped in yet — that's Phase 7). So a v0.1.0 → v0.1.3 Apply on a
// box that was installed at v0.1.0 produces a compose with v0.1.3 image
// tags but v0.1.0's structural content. Any new bind mounts / services
// shipped in v0.1.1+ won't land via that Apply alone.
//
// On its first startup post-Apply (i.e. when the binary version differs
// from the last-seen version), this method:
//  1. Renders the docker-compose.yml from the running binary's templates.
//  2. Compares to on-disk; if drift is detected, backs up the current
//     compose and atomically writes the regenerated content.
//  3. Calls `docker compose up -d` on non-data services (excluding self)
//     so the new mounts/services come live without requiring another
//     manual Apply.
//  4. Records the binary version to lastSeenVersionKey so subsequent
//     restarts at the same version are no-ops.
//
// Failures are logged but never propagated — the orchestrator must come
// up serving requests even if self-heal hits a snag. Worst case the next
// orchestrator restart re-detects and retries.
//
// Safety:
//   - Does nothing for "dev" or "" binary versions (avoids surprising
//     local development workflows).
//   - Does nothing when composeGen is nil (test rigs, partial wiring).
//   - Does nothing when a previous version key isn't set (fresh install).
//   - Does nothing when the version hasn't changed since last boot.
func (o *Orchestrator) SelfHealComposeOnVersionTransition(
	ctx context.Context,
	binaryVersion string,
) {
	hasComposeGen := o.composeGen != nil
	hasComposePath := len(o.cfg.ComposePaths) > 0

	// First pass: decide based on guards alone (no Valkey read needed yet).
	if act := decideSelfHealAction("", binaryVersion, hasComposeGen, hasComposePath); act == selfHealSkip {
		o.logger.Info("self-heal: skipping (preconditions not met)",
			"version", binaryVersion,
			"compose_gen", hasComposeGen,
			"compose_path", hasComposePath)
		return
	}

	prev, err := o.readLastSeenVersion(ctx)
	if err != nil {
		o.logger.Warn("self-heal: failed to read last-seen version (treating as fresh install, no heal)",
			"error", err)
		_ = o.writeLastSeenVersion(ctx, binaryVersion)
		return
	}

	switch decideSelfHealAction(prev, binaryVersion, hasComposeGen, hasComposePath) {
	case selfHealSkip:
		// Steady state — same version as last boot.
		return
	case selfHealReconcile:
		if prev == "" {
			o.logger.Info("self-heal: no prior version recorded, checking compose drift (covers upgrade path where old orchestrator never wrote the key)",
				"current", binaryVersion)
		} else {
			o.logger.Info("self-heal: version transition detected, checking compose drift",
				"prev", prev, "current", binaryVersion)
		}
		// Fall through to reconcile path below.
	}

	// Use a colocated backup path so it lives next to other apply backups.
	// Timestamped to avoid clobbering an in-flight Apply's backup (paranoid;
	// self-heal runs at startup so no Apply should be running).
	backupPath := filepath.Join(
		o.cfg.SnapshotDir,
		fmt.Sprintf("self-heal-%s-compose.yml", time.Now().UTC().Format("2006-01-02T15-04-05")),
	)

	rewritten, err := RegenerateCompose(
		ctx,
		o.cfg.ComposePaths[0],
		backupPath,
		binaryVersion,
		o.composeGen,
	)
	if err != nil {
		o.logger.Error("self-heal: regenerate failed (continuing startup)",
			"error", err)
		// Don't update last-seen-version — let next boot retry.
		return
	}
	if !rewritten {
		o.logger.Info("self-heal: on-disk compose already matches templates, no action needed")
		if writeErr := o.writeLastSeenVersion(ctx, binaryVersion); writeErr != nil {
			o.logger.Warn("self-heal: failed to update last-seen version", "error", writeErr)
		}
		return
	}

	o.logger.Info("self-heal: compose regenerated, recreating non-data services to pick up changes",
		"backup", backupPath, "services", VectisImageServicesExcludingSelf())

	if err := o.docker.ApplyComposeServices(ctx, VectisImageServicesExcludingSelf()); err != nil {
		o.logger.Error("self-heal: compose apply failed — rolling compose back",
			"error", err)
		if restoreErr := RestoreComposeBackup(o.cfg.ComposePaths[0], backupPath); restoreErr != nil {
			o.logger.Error("self-heal: CRITICAL — restore failed too, manual recovery may be needed",
				"backup", backupPath,
				"restore_error", restoreErr,
			)
		}
		// Don't update last-seen-version — let next boot retry.
		return
	}

	o.logger.Info("self-heal: complete — non-data services running on regenerated compose",
		"version", binaryVersion)
	if writeErr := o.writeLastSeenVersion(ctx, binaryVersion); writeErr != nil {
		o.logger.Warn("self-heal: succeeded but failed to update last-seen version (will re-trigger next boot, expected to be a no-op)",
			"error", writeErr)
	}
}

func (o *Orchestrator) readLastSeenVersion(ctx context.Context) (string, error) {
	cmd := o.vk.B().Get().Key(lastSeenVersionKey).Build()
	resp := o.vk.Do(ctx, cmd)
	if err := resp.Error(); err != nil {
		// Treat valkey nil (key absent) as empty, not error.
		if errors.Is(err, valkey.Nil) {
			return "", nil
		}
		return "", err
	}
	return resp.ToString()
}

func (o *Orchestrator) writeLastSeenVersion(ctx context.Context, v string) error {
	cmd := o.vk.B().Set().Key(lastSeenVersionKey).Value(v).Build()
	return o.vk.Do(ctx, cmd).Error()
}
