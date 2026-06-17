package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
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
//  2. Renders the per-service config set (postfix/dovecot/rspamd/traefik/...)
//     under cfg.GeneratedConfigDir (when configGen is wired).
//  3. Compares both to on-disk; if drift is detected, backs up the current
//     content and atomically writes the regenerated content.
//  4. If anything changed, calls `docker compose up -d` on non-data services
//     (excluding self) so the new mounts/services come live without
//     requiring another manual Apply.
//  5. Records the binary version to lastSeenVersionKey so subsequent
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
//   - Config regen is best-effort additive: when configGen is nil we still
//     run compose regen (covers v0.1.3-style transitions where this layer
//     wasn't yet wired).
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
			o.logger.Info("self-heal: no prior version recorded, checking compose+config drift (covers upgrade path where old orchestrator never wrote the key)",
				"current", binaryVersion)
		} else {
			o.logger.Info("self-heal: version transition detected, checking compose+config drift",
				"prev", prev, "current", binaryVersion)
		}
		// Fall through to reconcile path below.
	}

	// Mount-config precondition. Legacy installs (v0.1.0/v0.1.1/v0.1.2/v0.1.3
	// templates) created the orchestrator container with /etc/vectis:ro and no
	// /var/vectis/generated mount at all. Self-heal can't write through those
	// mounts — RegenerateCompose / RegenerateConfigs both fail "read-only file
	// system". v0.1.6 detects the situation up-front and skips cleanly with a
	// loud, actionable log message rather than partial-failing on every boot.
	// Don't update lastSeenVersion here so the next orchestrator restart
	// retries (after the operator recreates the container against the v0.1.6
	// template).
	if issues := CheckOrchestratorMounts(o.cfg.ComposePaths[0], o.cfg.GeneratedConfigDir); len(issues) > 0 {
		o.logger.Error("self-heal: skipping — orchestrator container is missing required bind mounts (legacy install detected)",
			"version", binaryVersion,
			"issues", issues,
			"remediation", MountIssuesRemediation(issues))
		return
	}

	// Phantom-container pre-check. Containers running outside the configured
	// compose project (or under a different compose file) hold the project's
	// network endpoints open. `compose up -d` fed into that state turns into
	// a partial-stop cascade: the new endpoint can't bind, services restart
	// in degraded order, and recovery becomes a manual job. Refuse-and-skip
	// is safer — operator inspects + cleans up phantoms, then next boot
	// re-runs self-heal.
	// See feedback_phantom_containers_block_self_heal.md.
	if phantoms, err := o.docker.listPhantomContainers(ctx); err != nil {
		o.logger.Warn("self-heal: phantom-container probe failed (continuing — non-fatal)",
			"error", err)
	} else if len(phantoms) > 0 {
		o.logger.Error("self-heal: skipping — phantom containers attached to vectis networks (will block compose up -d)",
			"version", binaryVersion,
			"phantoms", phantoms,
			"remediation", "inspect each container with `docker inspect <name>`; if it's a stale or external attachment, `docker rm -f <name>` and restart the orchestrator. The next boot will retry self-heal.")
		return
	}

	// Shared timestamp keeps the per-stage backups colocated and easy to
	// pair up during forensics.
	ts := time.Now().UTC().Format("2006-01-02T15-04-05")
	composeBackupPath := filepath.Join(
		o.cfg.SnapshotDir,
		fmt.Sprintf("self-heal-%s-compose.yml", ts),
	)
	configsBackupDir := filepath.Join(
		o.cfg.SnapshotDir,
		fmt.Sprintf("self-heal-%s-configs", ts),
	)

	composeRewritten, err := RegenerateCompose(
		ctx,
		o.cfg.ComposePaths[0],
		composeBackupPath,
		binaryVersion,
		o.composeGen,
	)
	if err != nil {
		o.logger.Error("self-heal: compose regenerate failed (continuing startup)",
			"error", err)
		// Don't update last-seen-version — let next boot retry.
		return
	}

	configsRewritten := false
	var configsChanged []string
	if o.configGen != nil && o.cfg.GeneratedConfigDir != "" {
		configsRewritten, configsChanged, err = RegenerateConfigs(
			ctx,
			o.cfg.GeneratedConfigDir,
			configsBackupDir,
			binaryVersion,
			o.configGen,
		)
		if err != nil {
			o.logger.Error("self-heal: config regenerate failed — restoring any partial changes",
				"error", err,
				"changed_so_far", configsChanged)
			if restoreErr := RestoreConfigsBackup(o.cfg.GeneratedConfigDir, configsBackupDir, configsChanged); restoreErr != nil {
				o.logger.Error("self-heal: CRITICAL — config restore failed",
					"backup", configsBackupDir, "restore_error", restoreErr)
			}
			if composeRewritten {
				if restoreErr := RestoreComposeBackup(o.cfg.ComposePaths[0], composeBackupPath); restoreErr != nil {
					o.logger.Error("self-heal: CRITICAL — compose restore failed too",
						"backup", composeBackupPath, "restore_error", restoreErr)
				}
			}
			// Don't update last-seen-version — let next boot retry.
			return
		}
	} else if o.configGen == nil {
		o.logger.Info("self-heal: config generator not wired — skipping per-service config regen",
			"version", binaryVersion)
	}

	// One-time DKIM key migration. The dkim dir moved from a named volume to a
	// host bind mount; copy any volume-only keys to the host path so no domain
	// loses its signing key. This MUST run on EVERY self-heal pass, regardless
	// of whether compose/config drifted — hence it sits BEFORE the no-action
	// early-return below, not inside the drift path. Reason: with
	// render-from-target upgrades (v0.1.25+), apply Phase 3.5 already rewrote
	// the compose to the host-mount form and recreated rspamd/postfix against it
	// BEFORE this (new) orchestrator booted. So composeRewritten is false here,
	// yet the keys can still be stranded in the legacy volume while the running
	// services read an empty/partial host mount. Idempotent, no-op once the
	// legacy volume is gone, best-effort (never blocks the upgrade).
	// (Bug found by the v0.1.27 mx1 canary, 2026-06-13: vectiscloud.com lost
	// signing because this previously ran only when drift was detected.)
	dkimCopied, err := o.docker.MigrateLegacyDKIMVolume(ctx)
	if err != nil {
		o.logger.Warn("self-heal: legacy DKIM volume migration failed — api-added domains may sign unsigned until keys are copied to /var/vectis/dkim manually",
			"error", err)
	}

	if !composeRewritten && !configsRewritten {
		// Apply Phase 3.5 already recreated the signing services onto the host
		// mount. If we just copied stranded keys into it, those running services
		// don't see them yet — restart rspamd + postfix to close the unsigned
		// window. When nothing was copied this whole branch is a pure no-op pass.
		if dkimCopied {
			signing := []string{containerName("rspamd"), containerName("postfix")}
			o.logger.Info("self-heal: migrated stranded DKIM keys to host; restarting signing services to pick them up",
				"containers", signing)
			if rerr := o.docker.RestartContainers(ctx, signing); rerr != nil {
				o.logger.Warn("self-heal: signing-service restart after DKIM migration failed (manual `docker restart vectis-rspamd vectis-postfix` may be needed)",
					"error", rerr)
			}
		}
		o.logger.Info("self-heal: on-disk compose+configs already match templates, no action needed")
		if writeErr := o.writeLastSeenVersion(ctx, binaryVersion); writeErr != nil {
			o.logger.Warn("self-heal: failed to update last-seen version", "error", writeErr)
		}
		return
	}

	o.logger.Info("self-heal: drift fixed, recreating non-data services to pick up changes",
		"compose_rewritten", composeRewritten,
		"configs_rewritten", configsRewritten,
		"configs_changed", configsChanged,
		"compose_backup", composeBackupPath,
		"configs_backup", configsBackupDir,
		"services", VectisImageServicesExcludingSelf())

	if err := o.docker.ApplyComposeServices(ctx, VectisImageServicesExcludingSelf()); err != nil {
		o.logger.Error("self-heal: compose apply failed — rolling everything back",
			"error", err)
		if composeRewritten {
			if restoreErr := RestoreComposeBackup(o.cfg.ComposePaths[0], composeBackupPath); restoreErr != nil {
				o.logger.Error("self-heal: CRITICAL — compose restore failed, manual recovery may be needed",
					"backup", composeBackupPath, "restore_error", restoreErr)
			}
		}
		if configsRewritten {
			if restoreErr := RestoreConfigsBackup(o.cfg.GeneratedConfigDir, configsBackupDir, configsChanged); restoreErr != nil {
				o.logger.Error("self-heal: CRITICAL — configs restore failed, manual recovery may be needed",
					"backup", configsBackupDir, "restore_error", restoreErr)
			}
		}
		// Don't update last-seen-version — let next boot retry.
		return
	}

	// `compose up -d` is a no-op when the image and compose-defined config are
	// unchanged, so containers keep their old bind-mount inodes / cached state.
	// `docker container restart` re-resolves them at start time. Two reasons to
	// restart a service here:
	//   - its single-file config was atomically replaced (postfix main.cf,
	//     dovecot.conf, rspamd maps, etc) — compose up -d above no-op'd it; and
	//   - rspamd+postfix when we just copied stranded DKIM keys into the host
	//     bind dir: ApplyComposeServices may have no-op'd them too (image +
	//     compose-config unchanged), so they wouldn't pick the keys up without
	//     an explicit restart. Restart whenever dkimCopied, regardless of which
	//     services drifted.
	// Deduped so a service that qualifies on both counts restarts once. Restart
	// failure is non-fatal: the changes are written, just inactive until a
	// future restart. (config restart: 2026-05-10 v0.1.11-rc2 sa1001 walkthrough;
	// DKIM restart: v0.1.27 mx1 canary 2026-06-13.)
	restartSet := map[string]struct{}{}
	if configsRewritten && len(configsChanged) > 0 {
		for _, c := range containerNamesForConfigPaths(configsChanged) {
			restartSet[c] = struct{}{}
		}
	}
	if dkimCopied {
		restartSet[containerName("rspamd")] = struct{}{}
		restartSet[containerName("postfix")] = struct{}{}
	}
	if len(restartSet) > 0 {
		targets := make([]string, 0, len(restartSet))
		for c := range restartSet {
			targets = append(targets, c)
		}
		sort.Strings(targets)
		o.logger.Info("self-heal: restarting containers to pick up new bind-mounted configs/keys",
			"containers", targets, "configs_changed", configsChanged, "dkim_copied", dkimCopied)
		if err := o.docker.RestartContainers(ctx, targets); err != nil {
			o.logger.Warn("self-heal: container restart failed (changes written, manual `docker restart` may be required)",
				"error", err, "containers", targets)
		}
	}

	o.logger.Info("self-heal: complete — non-data services running on regenerated compose+configs",
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

// servicesForConfigPaths maps configsChanged rel-paths to the vectis-*
// SERVICE names whose bind-mounted configs were touched. RegenerateConfigs
// writes files like "postfix/main.cf", "rspamd/maps/allow_domain.map",
// "dovecot/dovecot.conf" — the first path segment is always the service name.
// Result is deduplicated, sorted (deterministic for tests + log lines), and
// filtered to vectis-* image services *excluding* orchestrator (we never
// self-restart) and excluding postgres/valkey (data services live outside
// VectisImageServices anyway). Any first-segment that isn't a known vectis-*
// service is silently dropped — we'd rather miss a niche config-touched
// service than restart something unexpected.
func servicesForConfigPaths(paths []string) []string {
	known := make(map[string]struct{}, len(VectisImageServicesExcludingSelf()))
	for _, s := range VectisImageServicesExcludingSelf() {
		known[s] = struct{}{}
	}
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		first, _, ok := strings.Cut(p, "/")
		if !ok || first == "" {
			continue
		}
		if _, ok := known[first]; !ok {
			continue
		}
		seen[first] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// containerNamesForConfigPaths is servicesForConfigPaths mapped to container
// names (vectis-<service>), for callers that drive `docker container restart`.
func containerNamesForConfigPaths(paths []string) []string {
	svcs := servicesForConfigPaths(paths)
	out := make([]string, len(svcs))
	for i, s := range svcs {
		out[i] = containerName(s)
	}
	return out
}

// configRestartTargets returns the services whose bind-mounted configs changed
// during Apply's Phase 3.6 but that were NOT recreated by an image bump in
// Phase 4.3 — i.e. the ones `docker compose up -d` no-op'd (unchanged image +
// compose), so they still hold the OLD single-file bind-mount inodes and need
// an explicit `docker restart` to pick up the regenerated config. Image-bumped
// services are excluded because their recreate already re-resolved the mounts;
// restarting them again would be a redundant bounce. Returns service names,
// sorted (inherited from servicesForConfigPaths).
//
// This ports self-heal's `configsChanged → RestartContainers` step to Apply,
// closing the gap where a pure config-only delta (no image bump) — e.g. webmail
// or cert-extractor, which Phase 4.2 never stops — silently kept stale config.
// See feedback_bind_mount_edits.md.
func configRestartTargets(configsChanged []string, imageBumped map[string]bool) []string {
	out := make([]string, 0, len(configsChanged))
	for _, svc := range servicesForConfigPaths(configsChanged) {
		if imageBumped[svc] {
			continue
		}
		out = append(out, svc)
	}
	return out
}
