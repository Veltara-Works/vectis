package orchestrator

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/valkey-io/valkey-go"

	"github.com/Veltara-Works/vectis/internal/database"
	"github.com/Veltara-Works/vectis/internal/types"
)

// Constants for the rc36 orchestrator self-replace flow (Phase 7 of Apply).
//
// selfUpgradeHelperDelay: how long the helper sleeps after spawn before
// running `docker compose up -d orchestrator`. Gives this Apply goroutine
// time to return and the client to render a "completed" state before the
// orchestrator container is swapped.
//
// selfUpgradeCompletionSlack: extra seconds we add on top of the delay when
// publishing the "expected completion" timestamp to valkey, covering the
// time docker takes to actually stop + start the orchestrator container
// (typically 5–10s) plus a small safety margin.
//
// selfUpgradeKeyTTLExtra: TTL buffer on top of delay so the key lingers
// briefly for the UI to detect "we just finished" even if polling is slow.
//
// selfUpgradeUntilKey: Valkey key name surfaced to the UI via
// GET /api/v1/orchestrator/status so the Updates page can render a
// countdown banner instead of showing a seemingly-stalled upgrade.
const (
	selfUpgradeHelperDelay     = 30 * time.Second
	selfUpgradeCompletionSlack = 30 * time.Second
	selfUpgradeKeyTTLExtra     = 60 * time.Second
	selfUpgradeUntilKey        = "orchestrator:self_upgrade_until"
)

// ComposeGenerator returns the rendered docker-compose.yml content for the
// given release tag. Empty releaseTag means "use whatever Version is baked
// into the orchestrator binary" (i.e. don't override the template's default
// — useful for offline plans where release-channel discovery failed).
//
// Injected via Orchestrator.SetComposeGenerator so the orchestrator package
// stays decoupled from internal/engine, internal/config, and
// internal/repository (which would otherwise create import cycles via
// shared transitive deps).
type ComposeGenerator func(ctx context.Context, releaseTag string) ([]byte, error)

// Orchestrator is the core state machine that manages system updates.
// It is the only component with Docker socket access and enforces
// serialised execution via Postgres advisory locks per Spec D.
type Orchestrator struct {
	mu     sync.Mutex
	plan   *Plan
	lastOp *Operation

	sm         *StateMachine
	cfg        Config
	db         *pgxpool.Pool
	vk         valkey.Client
	docker     *DockerManager
	snap       *SnapshotManager
	logger     *slog.Logger
	composeGen ComposeGenerator // set by main.go; nil = legacy tag-rewrite path
	configGen  ConfigGenerator  // set by main.go; nil = self-heal skips per-service config regen
}

// New creates and initialises a new Orchestrator.
// It recovers state from Postgres on startup (Spec D.4).
func New(ctx context.Context, db *pgxpool.Pool, vk valkey.Client, cfg Config, logger *slog.Logger) (*Orchestrator, error) {
	sm, err := NewStateMachine(ctx, db, vk, logger.With("component", "state_machine"))
	if err != nil {
		return nil, fmt.Errorf("init state machine: %w", err)
	}

	return &Orchestrator{
		sm:     sm,
		cfg:    cfg,
		db:     db,
		vk:     vk,
		docker: NewDockerManager(cfg, logger.With("component", "docker")),
		snap:   NewSnapshotManager(cfg, logger.With("component", "snapshot")),
		logger: logger,
	}, nil
}

// SetComposeGenerator wires up the callback that Phase 3.5 of Apply uses to
// regenerate /etc/vectis/docker-compose.yml from the embedded templates.
// Must be called once at startup, before the first Apply. If nil (or never
// set), Phase 3.5 falls back to the legacy tag-only rewrite path which only
// patches `image:` lines and cannot pick up structural template changes
// (new bind mounts, new services, env tweaks).
func (o *Orchestrator) SetComposeGenerator(gen ComposeGenerator) {
	o.composeGen = gen
}

// SetConfigGenerator wires up the callback that self-heal uses to regenerate
// per-service config files (postfix/dovecot/rspamd/traefik/...) under
// cfg.GeneratedConfigDir. When nil, self-heal still regenerates compose but
// leaves on-disk service configs alone — so v0.1.5's prod-drift fixes only
// apply when this is wired by main.go.
func (o *Orchestrator) SetConfigGenerator(gen ConfigGenerator) {
	o.configGen = gen
}

// State returns the current orchestrator state.
func (o *Orchestrator) State() State {
	return o.sm.State()
}

// LastOperation returns the most recent operation, if any.
func (o *Orchestrator) LastOperation() *Operation {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.lastOp
}

// CurrentPlan returns the current stored plan, if any.
func (o *Orchestrator) CurrentPlan() *Plan {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.plan
}

// Status returns the current state and the last operation info (Spec D.10).
func (o *Orchestrator) Status() StatusResponse {
	o.mu.Lock()
	defer o.mu.Unlock()
	return StatusResponse{
		State:         o.sm.State(),
		LastOperation: o.lastOp,
	}
}

// SelfUpgradeUntil returns the RFC3339 timestamp at which the currently
// pending orchestrator self-replacement is expected to complete, or nil if
// no self-replacement is in flight.
//
// Read from the Valkey key orchestrator:self_upgrade_until, which is written
// by Apply's Phase 7 immediately after a self-replace helper is spawned. The
// key has a TTL slightly longer than the helper's scheduled delay so it
// auto-cleans without any explicit removal — even if the orchestrator itself
// is replaced (the new orchestrator has no record of its prior life's
// helper spawn, but the TTL keeps ticking down and Valkey will drop the key
// at the right time regardless).
//
// Surfaced on GET /orchestrator/status so the UI can render a countdown
// banner during the ~30s helper-delay window, preventing users from thinking
// an Apply has stalled when it's actually in its final orchestrator-swap step.
func (o *Orchestrator) SelfUpgradeUntil(ctx context.Context) *time.Time {
	cmd := o.vk.B().Get().Key(selfUpgradeUntilKey).Build()
	s, err := o.vk.Do(ctx, cmd).ToString()
	if err != nil {
		if !valkey.IsValkeyNil(err) {
			o.logger.Warn("failed to read self_upgrade_until from valkey", "error", err)
		}
		return nil
	}
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		o.logger.Warn("self_upgrade_until valkey value is not RFC3339", "value", s, "error", err)
		return nil
	}
	if time.Now().UTC().After(t) {
		// Window has already passed; don't surface a stale timestamp. Valkey
		// will drop the key via TTL shortly.
		return nil
	}
	return &t
}

// Health returns a simple health check response (Spec D.10).
func (o *Orchestrator) Health() HealthResponse {
	state := o.sm.State()
	healthy := state != StateFailed
	return HealthResponse{
		Healthy: healthy,
		State:   state,
	}
}

// acquireAdvisoryLock takes the orchestrator's Postgres advisory lock so only
// one operation runs at a time (Spec D.4).
//
// pg_advisory_lock is SESSION-scoped: the lock is owned by the backend
// connection that took it and must be released on that SAME connection. Running
// it via the pool (o.db.Exec) grabs an arbitrary connection per call, so the
// lock and unlock could land on different sessions — giving no mutual exclusion
// and leaking the lock. We therefore acquire ONE dedicated connection from the
// pool and hold it for the whole locked operation. The returned func releases
// the lock on that connection and returns it to the pool; callers must defer it.
func (o *Orchestrator) acquireAdvisoryLock(ctx context.Context) (func(), error) {
	conn, err := o.db.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("acquire db connection for advisory lock: %w", err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock(1)"); err != nil {
		conn.Release()
		return nil, fmt.Errorf("acquire advisory lock: %w", err)
	}
	return func() {
		// Release on the SAME connection. Use a cancel-free context so a
		// cancelled operation still drops the lock rather than leaking it.
		if _, err := conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock(1)"); err != nil {
			o.logger.Error("failed to release advisory lock", "error", err)
		}
		conn.Release()
	}, nil
}

// configHash computes a SHA-256 hash of the current docker-compose file
// as a proxy for the "desired state" config hash.
func (o *Orchestrator) configHash() (string, error) {
	// Read all configured compose files in order and hash them as one blob.
	// In a real implementation this would also incorporate config.yaml.
	// For now the compose files are the source of truth for orchestrator's
	// view of the desired state.
	h := sha256.New()
	for _, path := range o.cfg.ComposePaths {
		data, err := readFileBytes(path)
		if err != nil {
			return "", fmt.Errorf("read compose file %q for hashing: %w", path, err)
		}
		h.Write(data)
		// Delimiter between files so concatenated contents can't collide.
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Plan computes the diff between current and desired state (Spec D.3, D.9).
// This is a synchronous operation that blocks until complete.
func (o *Orchestrator) Plan(ctx context.Context) (*Plan, error) {
	release, err := o.acquireAdvisoryLock(ctx)
	if err != nil {
		return nil, fmt.Errorf("orchestrator busy: %w", err)
	}
	defer release()

	// Validate current state allows planning.
	if !o.sm.State().CanPlan() {
		return nil, &ErrInvalidTransition{From: o.sm.State(), Op: "plan"}
	}

	if err := o.sm.Transition(ctx, StatePlanning); err != nil {
		return nil, err
	}

	o.logger.Info("computing plan")

	cfgHash, err := o.configHash()
	if err != nil {
		o.sm.Transition(ctx, StateFailed) //nolint:errcheck
		return nil, fmt.Errorf("compute config hash: %w", err)
	}

	// Get current container versions as the baseline.
	versions, err := o.docker.GetContainerVersions(ctx)
	if err != nil {
		o.sm.Transition(ctx, StateFailed) //nolint:errcheck
		return nil, fmt.Errorf("get container versions: %w", err)
	}

	// Diff running container images against compose-declared images to build
	// the Change list. Services with mismatched image refs get a PlanChange.
	// Services not declared in compose (e.g. webmail on some deploys) are
	// skipped — they aren't orchestrator-managed.
	//
	// A failure to read the compose file MUST be a hard error: silently
	// returning an empty plan used to surface as "all services up to date"
	// in the UI, which gave users a false sense of currency when in fact
	// the orchestrator couldn't see their compose at all (see
	// deferred-items.md §10 blocker #4).
	desired, err := o.docker.composeImages(ctx)
	if err != nil {
		o.sm.Transition(ctx, StateFailed) //nolint:errcheck
		return nil, fmt.Errorf("read compose images: %w", err)
	}

	// Reject floating `:latest` tags on Vectis services. release.yml only
	// updates `:latest` on stable releases (see feedback_latest_tag_unbumped),
	// so an rc fix-forward can leave `:latest` pointing at an older release
	// than the running stack. Diffing against a floating tag is meaningless
	// — Apply would crash-loop api/orchestrator on migration mismatch when
	// `:latest` silently rewinds.
	for _, svc := range VectisImageServices {
		img, ok := desired[svc]
		if !ok {
			continue
		}
		if imageHasFloatingTag(img) {
			o.sm.Transition(ctx, StateFailed) //nolint:errcheck
			return nil, fmt.Errorf("plan refused: service %q is pinned to floating tag %q in compose; pin to an explicit release tag (e.g. v0.1.6) so Plan can compare against a stable target", svc, img)
		}
	}

	// Fetch the release-channel manifest and, on success, rewrite every
	// vectis-* image in `desired` to the lockstep tag. Diff then reports
	// "you're on rc21, released channel says rc24" — the actual point of
	// the Updates page for free self-hosted users (§10 blocker #4 goal).
	//
	// A fetch failure is non-fatal: Plan still reports compose-vs-running
	// drift from local state alone, with a warning attached so the user
	// knows the result may be stale. Unlike compose-read failures (which
	// produce a wholly-wrong plan), a missing release channel just means
	// we can't tell the user about newer versions — the local plan is
	// still correct for what it can see.
	var releaseTag string
	var warnings []string
	if o.cfg.ReleaseChannelURL != "" {
		releaseCtx, releaseCancel := context.WithTimeout(ctx, 10*time.Second)
		m, ferr := fetchReleaseManifest(releaseCtx, &http.Client{}, o.cfg.ReleaseChannelURL)
		releaseCancel()
		if ferr != nil {
			o.logger.Warn("release channel fetch failed; planning from local compose only",
				"url", o.cfg.ReleaseChannelURL, "error", ferr)
			warnings = append(warnings, fmt.Sprintf("release channel unavailable: %v (plan shows local compose-vs-running drift only)", ferr))
		} else {
			releaseTag = m.Latest
			for svc, img := range desired {
				desired[svc] = rewriteReleaseTag(img, m.Latest)
			}
		}
	}

	var changes []PlanChange
	for _, svc := range VectisImageServices {
		declared, ok := desired[svc]
		if !ok {
			continue // Not in compose — picked up by structural diff below.
		}
		running := versions[svc]
		if running == declared {
			continue
		}
		changeType := "update"
		if running == "" {
			changeType = "create"
		}
		changes = append(changes, PlanChange{
			Service:  svc,
			Type:     changeType,
			OldImage: running,
			NewImage: declared,
		})
	}

	// Structural diff: catches profile-gated services that appear/disappear
	// under config.yaml control (e.g. clamav.profile flips). Without this,
	// Plan returns changes:null for config-only changes and Apply short-
	// circuits before Phase 3.5 — the operator's config.yaml edit never
	// lands on disk.
	structural, structuralWarnings := o.detectStructuralChanges(ctx, releaseTag, desired)
	changes = append(changes, structural...)
	warnings = append(warnings, structuralWarnings...)

	plan := &Plan{
		ID:               types.NewUUIDv7(),
		CreatedAt:        time.Now().UTC(),
		ConfigHash:       cfgHash,
		BaselineVersions: versions,
		Changes:          changes,
		MigrationsUp:     o.detectPendingMigrations(),
		ReleaseTag:       releaseTag,
		Warnings:         warnings,
	}

	// Record the operation.
	planSummary := map[string]any{
		"config_hash":       cfgHash,
		"baseline_versions": versions,
		"changes":           changes,
		"migrations_up":     plan.MigrationsUp,
	}
	opID, err := o.sm.RecordOperation(ctx, "plan", "completed", cfgHash, planSummary, versions)
	if err != nil {
		o.logger.Error("failed to record plan operation", "error", err)
	} else {
		_ = o.sm.CompleteOperation(ctx, opID, "completed", "", "")
	}

	// Transition back to idle (plan complete).
	if err := o.sm.Transition(ctx, StateIdle); err != nil {
		return nil, fmt.Errorf("transition to idle after plan: %w", err)
	}

	o.mu.Lock()
	o.plan = plan
	now := time.Now().UTC()
	o.lastOp = &Operation{
		JobID:     plan.ID,
		Type:      "plan",
		State:     StateIdle,
		StartedAt: plan.CreatedAt,
		EndedAt:   &now,
	}
	o.mu.Unlock()

	o.logger.Info("plan complete", "plan_id", plan.ID, "changes", len(plan.Changes))
	return plan, nil
}

// Apply executes the stored plan using the full 6-phase apply sequence
// per Spec D.6. It acquires the advisory lock and transitions through:
// idle -> validating -> applying -> idle (or rolling_back/failed on error).
func (o *Orchestrator) Apply(ctx context.Context) (string, error) {
	return o.ApplyWithJobID(ctx, types.NewUUIDv7())
}

// ApplyWithJobID is like Apply but uses a pre-generated job ID so the caller
// can return it to clients before the advisory lock is acquired.
func (o *Orchestrator) ApplyWithJobID(ctx context.Context, jobID string) (string, error) {
	release, err := o.acquireAdvisoryLock(ctx)
	if err != nil {
		return "", fmt.Errorf("orchestrator busy: %w", err)
	}
	defer release()

	// Check state.
	if !o.sm.State().CanApply() {
		return "", &ErrInvalidTransition{From: o.sm.State(), Op: "apply"}
	}

	o.mu.Lock()
	plan := o.plan
	o.mu.Unlock()

	if plan == nil {
		return "", fmt.Errorf("no plan available; run Plan first")
	}

	// Mount-config precondition. Apply MUST be able to write through
	// /etc/vectis (Phase 3.5 atomic compose rewrite) and /var/vectis/generated
	// (per-service config regen). Pre-v0.1.5 templates created the orchestrator
	// container without these mounts; carrying through to Phase 3.5 produces
	// a "read-only file system" error mid-Apply, which leaves the system
	// half-upgraded with no clean rollback.
	// See feedback_v0.1.5_selfheal_legacy_install_broken.md.
	if len(o.cfg.ComposePaths) > 0 {
		if issues := CheckOrchestratorMounts(o.cfg.ComposePaths[0], o.cfg.GeneratedConfigDir); len(issues) > 0 {
			return "", fmt.Errorf("apply refused: %s", MountIssuesRemediation(issues))
		}
	}

	// Apply timeout for the entire operation.
	applyCtx, cancel := context.WithTimeout(ctx, o.cfg.ApplyTimeout)
	defer cancel()

	// Record the operation as running.
	opID, err := o.sm.RecordOperation(applyCtx, "apply", "running", plan.ConfigHash, nil, plan.BaselineVersions)
	if err != nil {
		return "", fmt.Errorf("record apply operation: %w", err)
	}

	// No-op short-circuit: if the plan has no container or migration changes,
	// there's nothing to snapshot, pull, or restart. Complete the op as a no-op
	// and stay in idle. Prevents accidental service restarts on zero-diff plans.
	if plan.IsEmpty() {
		o.logger.Info("apply: plan has no changes, short-circuiting", "job_id", jobID)
		_ = o.sm.CompleteOperation(applyCtx, opID, "completed", "", "no-op: plan had no changes")
		o.mu.Lock()
		o.plan = nil
		now := time.Now().UTC()
		o.lastOp.State = StateIdle
		o.lastOp.EndedAt = &now
		o.mu.Unlock()
		return jobID, nil
	}

	o.mu.Lock()
	o.lastOp = &Operation{
		JobID:     jobID,
		Type:      "apply",
		State:     StateValidating,
		StartedAt: time.Now().UTC(),
	}
	o.mu.Unlock()

	// ===== PHASE 1: VALIDATE =====
	if err := o.sm.Transition(applyCtx, StateValidating); err != nil {
		return "", err
	}

	o.logger.Info("phase 1: validating", "job_id", jobID)

	// Check plan staleness (Spec D.9).
	currentHash, hashErr := o.configHash()
	currentVersions, verErr := o.docker.GetContainerVersions(applyCtx)
	if hashErr != nil || verErr != nil {
		o.failApply(applyCtx, opID, jobID, "validation failed: cannot read current state")
		return "", fmt.Errorf("validation failed: hash_err=%v, ver_err=%v", hashErr, verErr)
	}

	if plan.IsStale(currentHash, currentVersions) {
		o.failApply(applyCtx, opID, jobID, "PLAN_STALE: system state changed since plan was computed")
		return "", fmt.Errorf("PLAN_STALE: system state changed since plan was computed")
	}

	// ===== PHASE 2: SNAPSHOT =====
	if err := o.sm.Transition(applyCtx, StateApplying); err != nil {
		return "", err
	}

	o.logger.Info("phase 2: creating database snapshot", "job_id", jobID)

	snapshotPath, err := o.snap.CreateSnapshot(applyCtx)
	if err != nil {
		// No changes made yet — go straight to failed (no rollback needed).
		o.failApply(applyCtx, opID, jobID, fmt.Sprintf("snapshot failed: %v", err))
		return "", fmt.Errorf("snapshot failed: %w", err)
	}

	// Update the operation with the snapshot path.
	_ = o.sm.CompleteOperation(applyCtx, opID, "running", snapshotPath, "")

	o.mu.Lock()
	o.lastOp.SnapshotPath = snapshotPath
	o.mu.Unlock()

	// ===== PHASE 3: MIGRATE =====
	o.logger.Info("phase 3: running database migrations", "job_id", jobID)

	if plan.MigrationsUp > 0 {
		migrateCtx, migrateCancel := context.WithTimeout(applyCtx, o.cfg.DBMigrationTimeout)
		err = o.runMigrations(migrateCtx)
		migrateCancel()

		if err != nil {
			o.logger.Error("migration failed, initiating rollback", "error", err)
			rollbackErr := o.doRollback(applyCtx, snapshotPath)
			if rollbackErr != nil {
				o.failApply(applyCtx, opID, jobID, fmt.Sprintf("migration failed and rollback also failed: migrate=%v, rollback=%v", err, rollbackErr))
				return "", fmt.Errorf("migration and rollback both failed: %w", rollbackErr)
			}
			o.completeRollback(opID, snapshotPath, fmt.Sprintf("migration failed: %v", err))
			return jobID, fmt.Errorf("migration failed, rolled back: %w", err)
		}
	}

	// ===== PHASE 3.5: REGENERATE / REWRITE COMPOSE =====
	//
	// The on-disk compose file was written at install time with whatever
	// release tag was current *then*. Plan's Changes[] + plan.ReleaseTag
	// carry the target tags from the release channel. If we skipped this
	// step, `docker compose pull` at 4.1 would just re-pull whatever's
	// already in the file — so "Apply v0.1.0-rc29" after a Plan that says
	// "rc28 → rc29" would be a no-op on a box that was installed at rc28.
	// Surfaced end-to-end post-rc27 on sysadmin1001.
	//
	// Two paths:
	//   - composeGen set + plan.ReleaseTag non-empty → full regen from
	//     the orchestrator's embedded templates (RegenerateCompose).
	//     Picks up structural template changes (new bind mounts, new
	//     services, env tweaks) on top of the tag bump. Required for
	//     v0.1.2's per-domain spam mounts to land on upgrade without
	//     manual host-side compose patching (deferred-items.md §10).
	//   - composeGen unset OR plan.ReleaseTag empty → legacy tag-only
	//     rewrite (RewriteComposeTags). Preserves behaviour for
	//     release-channel-disabled installs and offline plans.
	//
	// Any failure here rolls back (DB + compose), same as every other
	// Apply phase. The backup path is derived from snapshotPath so
	// rollback can find it without a new persisted field.
	o.logger.Info("phase 3.5: rewriting compose with target tags", "job_id", jobID)

	// Select the renderer for this Apply. Default = the in-process generators
	// wired by main.go, which render from THIS (running) orchestrator's embedded
	// templates. When render-from-target is enabled and a release tag is known,
	// render the desired compose + configs from the TARGET release image's own
	// `vectis config generate` instead — so a template/healthcheck change shipped
	// in the target release lands during the very Apply that delivers it, instead
	// of being invisible until the next one (GH #47 bootstrap deadlock).
	//
	// On ANY render-from-target failure we log loudly and fall back to the
	// embedded-template generators: the Apply is then no worse than before this
	// change (it just can't pick up target-only template changes), rather than
	// failing outright.
	composeGen := o.composeGen
	configGen := o.configGen
	renderMode := "embedded-templates"
	if o.cfg.RenderFromTargetImage && plan.ReleaseTag != "" {
		composeYAML, cfgFiles, rErr := o.renderViaTargetImage(applyCtx, plan.ReleaseTag, jobID)
		if rErr != nil {
			o.logger.Warn("render-from-target failed; falling back to embedded templates (target-only template changes will NOT land this Apply)",
				"job_id", jobID, "release_tag", plan.ReleaseTag, "error", rErr)
		} else {
			renderMode = "target-image"
			composeGen = staticComposeGenerator(composeYAML)
			configGen = staticConfigGenerator(cfgFiles)
			o.logger.Info("rendered desired state from target release image",
				"job_id", jobID, "release_tag", plan.ReleaseTag, "config_files", len(cfgFiles))
		}
	}

	composePath := ""
	if len(o.cfg.ComposePaths) > 0 {
		composePath = o.cfg.ComposePaths[0]
	}
	if composePath != "" {
		backupPath := composeBackupPathFor(snapshotPath)
		var rewritten bool
		var rewriteErr error
		var mode string

		if composeGen != nil && plan.ReleaseTag != "" {
			mode = renderMode
			rewritten, rewriteErr = RegenerateCompose(applyCtx, composePath, backupPath, plan.ReleaseTag, composeGen)
		} else {
			mode = "tag-rewrite"
			rewritten, rewriteErr = RewriteComposeTags(composePath, plan.Changes, backupPath)
		}

		if rewriteErr != nil {
			o.logger.Error("compose rewrite failed, initiating rollback", "mode", mode, "error", rewriteErr)
			rollbackErr := o.doRollback(applyCtx, snapshotPath)
			if rollbackErr != nil {
				o.failApply(applyCtx, opID, jobID, fmt.Sprintf("compose rewrite failed and rollback also failed: mode=%s rewrite=%v, rollback=%v", mode, rewriteErr, rollbackErr))
				return "", fmt.Errorf("compose rewrite and rollback both failed: %w", rollbackErr)
			}
			o.completeRollback(opID, snapshotPath, fmt.Sprintf("compose rewrite failed (%s): %v", mode, rewriteErr))
			return jobID, fmt.Errorf("compose rewrite failed, rolled back: %w", rewriteErr)
		}
		if rewritten {
			o.logger.Info("compose rewritten",
				"mode", mode,
				"job_id", jobID,
				"backup", backupPath,
				"release_tag", plan.ReleaseTag,
				"change_count", len(plan.Changes),
			)
		} else {
			o.logger.Info("compose needed no rewrite (already matches target)", "mode", mode, "job_id", jobID)
		}
	}

	// ===== PHASE 3.6: REGENERATE PER-SERVICE CONFIGS =====
	//
	// Phase 3.5 rewrote docker-compose.yml — but the bind-mounts inside that
	// compose point at per-service config files under cfg.GeneratedConfigDir
	// (postfix/main.cf, dovecot/dovecot.conf, rspamd/*.conf, clamav/clamd.conf
	// when the profile is non-none, ...). Those files are only written by:
	//   - first-time install (`vectis install`),
	//   - the Updates UI's `vectis config apply` invocation, and
	//   - cross-version startup self-heal (compose_selfheal.RegenerateConfigs).
	//
	// None of those fire during a normal Apply, so a config-driven structural
	// change (e.g. clamav.profile flipping from "none" to "production",
	// detected by Plan's structural-drift loop) lands a compose entry whose
	// bind-mount source either doesn't exist (Docker silently creates an
	// empty dir) or carries stale content from when the service was last
	// rendered. Either way the new container fails to start, the healthcheck
	// fires, and the whole Apply rolls back. Reproduced on prod 2026-05-04
	// during the v0.1.7 → v0.1.8-rc1 walk: clamav rendered with
	// `Profile: none`, MaxThreads=0, empty knob values; clamd refused to
	// parse and never reached healthy.
	//
	// Fix: regenerate per-service configs alongside the compose rewrite,
	// before Phase 4 pulls images and starts containers. Backups go into a
	// per-snapshot configs/ subdir so doRollback can restore them on Apply
	// failure (paired with the existing compose backup restore).
	//
	// Skip path: configGen unset (legacy installs whose main.go didn't wire
	// SetConfigGenerator) — same fallback as Phase 3.5's compose path. The
	// regen is best-effort additive; configs simply stay where they are.
	// Captured at function scope so Phase 5.5 can restart the services whose
	// configs changed but that compose-up no-op'd (no image bump → stale
	// single-file bind-mount inodes). See configRestartTargets.
	var configsChanged []string
	if configGen != nil && len(o.cfg.GeneratedConfigDir) > 0 {
		o.logger.Info("phase 3.6: regenerating per-service configs", "job_id", jobID, "render_mode", renderMode)
		configBackupDir := configBackupDirFor(snapshotPath)
		var regenErr error
		_, configsChanged, regenErr = RegenerateConfigs(
			applyCtx,
			o.cfg.GeneratedConfigDir,
			configBackupDir,
			plan.ReleaseTag,
			configGen,
		)
		if regenErr != nil {
			o.logger.Error("config regen failed, initiating rollback", "error", regenErr)
			rollbackErr := o.doRollback(applyCtx, snapshotPath)
			if rollbackErr != nil {
				o.failApply(applyCtx, opID, jobID, fmt.Sprintf("config regen failed and rollback also failed: regen=%v, rollback=%v", regenErr, rollbackErr))
				return "", fmt.Errorf("config regen and rollback both failed: %w", rollbackErr)
			}
			o.completeRollback(opID, snapshotPath, fmt.Sprintf("config regen failed: %v", regenErr))
			return jobID, fmt.Errorf("config regen failed, rolled back: %w", regenErr)
		}
		if len(configsChanged) > 0 {
			o.logger.Info("per-service configs regenerated",
				"job_id", jobID,
				"backup_dir", configBackupDir,
				"release_tag", plan.ReleaseTag,
				"file_count", len(configsChanged),
			)
		} else {
			o.logger.Info("per-service configs needed no regen (already match templates)", "job_id", jobID)
		}
	}

	// ===== PHASE 4: UPDATE CONTAINERS =====
	o.logger.Info("phase 4: updating containers", "job_id", jobID)

	// 4.1 Pull new images. Must cover every service whose tag may have been
	// rewritten by Phase 3.5, not just dependency-ordered startup services —
	// otherwise orchestrator + cert-extractor get bumped in compose but their
	// new images are never pulled, so 4.3's `compose up -d` would either fail
	// or silently keep the old containers alive.
	if err := o.docker.PullImages(applyCtx, VectisImageServices); err != nil {
		o.logger.Error("image pull failed, initiating rollback", "error", err)
		rollbackErr := o.doRollback(applyCtx, snapshotPath)
		if rollbackErr != nil {
			o.failApply(applyCtx, opID, jobID, fmt.Sprintf("pull failed and rollback also failed: pull=%v, rollback=%v", err, rollbackErr))
			return "", fmt.Errorf("pull and rollback both failed: %w", rollbackErr)
		}
		o.completeRollback(opID, snapshotPath, fmt.Sprintf("image pull failed: %v", err))
		return jobID, fmt.Errorf("image pull failed, rolled back: %w", err)
	}

	// 4.2 Stop services in reverse dependency order. Postgres and valkey stay
	// up: phase 4.3 (compose up) can fail, and rollback phase 2 (psql restore)
	// needs postgres reachable. Originally every service was stopped here —
	// which made restore impossible and left the stack unrecoverable when
	// compose apply failed (see project_phase3_e2e_findings.md rollback run).
	stopOrder := NonDataStopOrder()
	if err := o.docker.StopServices(applyCtx, stopOrder); err != nil {
		o.logger.Error("stop services failed, initiating rollback", "error", err)
		rollbackErr := o.doRollback(applyCtx, snapshotPath)
		if rollbackErr != nil {
			o.failApply(applyCtx, opID, jobID, fmt.Sprintf("stop failed and rollback also failed: stop=%v, rollback=%v", err, rollbackErr))
			return "", fmt.Errorf("stop and rollback both failed: %w", rollbackErr)
		}
		o.completeRollback(opID, snapshotPath, fmt.Sprintf("stop services failed: %v", err))
		return jobID, fmt.Errorf("stop services failed, rolled back: %w", err)
	}

	// 4.3 Apply new docker-compose.yml for every vectis-* service EXCEPT the
	// orchestrator itself. Orchestrator's self-replacement is deferred to
	// Phase 7 (a detached helper container). If we ran `compose up -d` with
	// the full stack here, docker would SIGTERM the orchestrator mid-command
	// and this goroutine would die with it — 0.35s was all we got before the
	// kill on the rc33→rc35 walkthrough (GA blocker #9, fixed rc36).
	if err := o.docker.ApplyComposeServices(applyCtx, VectisImageServicesExcludingSelf()); err != nil {
		o.logger.Error("apply compose failed, initiating rollback", "error", err)
		rollbackErr := o.doRollback(applyCtx, snapshotPath)
		if rollbackErr != nil {
			o.failApply(applyCtx, opID, jobID, fmt.Sprintf("compose apply failed and rollback also failed: compose=%v, rollback=%v", err, rollbackErr))
			return "", fmt.Errorf("compose apply and rollback both failed: %w", rollbackErr)
		}
		o.completeRollback(opID, snapshotPath, fmt.Sprintf("compose apply failed: %v", err))
		return jobID, fmt.Errorf("compose apply failed, rolled back: %w", err)
	}

	// 4.4 Start services in dependency order (health checked inside StartServices).

	// ===== PHASE 5: HEALTH CHECK =====
	o.logger.Info("phase 5: starting services and checking health", "job_id", jobID)

	if err := o.docker.StartServices(applyCtx, ServiceStartOrder); err != nil {
		o.logger.Error("health check failed, initiating rollback", "error", err)
		o.sm.Transition(applyCtx, StateRollingBack) //nolint:errcheck
		rollbackErr := o.doRollback(applyCtx, snapshotPath)
		if rollbackErr != nil {
			o.failApply(applyCtx, opID, jobID, fmt.Sprintf("health check failed and rollback also failed: health=%v, rollback=%v", err, rollbackErr))
			return "", fmt.Errorf("health check and rollback both failed: %w", rollbackErr)
		}
		o.completeRollback(opID, snapshotPath, fmt.Sprintf("health check failed: %v", err))
		return jobID, fmt.Errorf("health check failed, rolled back: %w", err)
	}

	// ===== PHASE 5.5: RESTART CONFIG-ONLY-CHANGED SIDECARS =====
	//
	// `docker compose up -d` (Phase 4.3) is a no-op for a service whose image +
	// compose entry are unchanged and that is already RUNNING — it keeps the
	// container, which holds the OLD inode of any single-file bind-mounted config
	// (Phase 3.6 atomically replaced the file on the host, allocating a new
	// inode). Two sets of services are already covered: those Phase 4.2 stopped
	// get a fresh start in 4.3 (a `docker start` re-resolves the bind mount —
	// verified empirically), and image-bumped services are recreated. The gap is
	// services upped while still running and never stopped — webmail,
	// cert-extractor — on a pure config-only delta. Mirror self-heal: `docker
	// restart` re-resolves their mounts.
	//
	// Best-effort (non-fatal), like self-heal: the regenerated config is already
	// on disk, so a rare restart failure is logged with a remediation hint rather
	// than rolling back an otherwise-healthy Apply. These sidecars carry no
	// HEALTHCHECK (they're absent from ServiceStartOrder/ServiceHealthTimeouts),
	// so there's nothing to health-gate — WaitHealthy would just time out.
	// See feedback_bind_mount_edits.md.
	cycled := make(map[string]bool, len(NonDataStopOrder()))
	for _, s := range NonDataStopOrder() {
		cycled[s] = true
	}
	imageBumped := make(map[string]bool, len(plan.Changes))
	for _, c := range plan.Changes {
		imageBumped[c.Service] = true
	}
	if restartServices := configRestartTargets(configsChanged, imageBumped, cycled); len(restartServices) > 0 {
		containers := make([]string, len(restartServices))
		for i, svc := range restartServices {
			containers[i] = containerName(svc)
		}
		o.logger.Info("phase 5.5: restarting config-only-changed sidecars to pick up new bind-mounted configs",
			"job_id", jobID, "services", restartServices)
		if err := o.docker.RestartContainers(applyCtx, containers); err != nil {
			o.logger.Warn("phase 5.5: sidecar restart failed (config is on disk; a manual `docker restart` may be needed to activate it)",
				"job_id", jobID, "services", restartServices, "error", err)
		}
	}

	// ===== PHASE 6: COMPLETE =====
	o.logger.Info("phase 6: completing apply", "job_id", jobID)

	_ = o.sm.CompleteOperation(applyCtx, opID, "completed", snapshotPath, "")

	if err := o.sm.Transition(applyCtx, StateIdle); err != nil {
		return "", fmt.Errorf("transition to idle after apply: %w", err)
	}

	// Capture orchestrator's CURRENT image tag (still the pre-upgrade one —
	// we excluded it from Phase 4.3) before we null out the plan. Used in
	// Phase 7 as the helper's base image so the helper's docker CLI is
	// guaranteed-working. Also captured: whether orchestrator was in the
	// upgrade set at all — if not, Phase 7 is a no-op.
	orchestratorOldImage := plan.BaselineVersions["orchestrator"]
	orchestratorNeedsUpgrade := false
	for _, c := range plan.Changes {
		if c.Service == "orchestrator" {
			orchestratorNeedsUpgrade = true
			break
		}
	}

	o.mu.Lock()
	o.plan = nil // Plan consumed.
	now := time.Now().UTC()
	o.lastOp.State = StateIdle
	o.lastOp.EndedAt = &now
	o.mu.Unlock()

	o.logger.Info("apply complete", "job_id", jobID)

	// ===== PHASE 7: SPAWN SELF-REPLACE HELPER =====
	//
	// If orchestrator's image tag was changed by Phase 3.5 (i.e. Plan had an
	// orchestrator entry in Changes), we still need to recreate the
	// orchestrator container — but we can't do it from inside ourselves
	// (GA blocker #9 pre-rc36). Instead, spawn a detached helper container
	// that runs `docker compose up -d orchestrator` after a short delay,
	// giving this goroutine time to return and the UI a chance to render
	// "apply complete".
	//
	// Failure to spawn is logged but does NOT fail the Apply — Phase 6 has
	// already recorded success and the other 5 services are on the new tag.
	// User recovers by running `docker compose up -d orchestrator` manually
	// (same as pre-rc36 behaviour, but now the exception rather than the rule).
	if orchestratorNeedsUpgrade && orchestratorOldImage != "" {
		helperID, spawnErr := o.docker.SpawnSelfReplaceHelper(
			applyCtx, orchestratorOldImage,
			selfUpgradeHelperDelay, types.NewUUIDv7(),
		)
		if spawnErr != nil {
			o.logger.Error("failed to spawn orchestrator self-replace helper — orchestrator will stay on old tag until manually recreated",
				"error", spawnErr,
				"recovery_hint", "run `docker compose up -d orchestrator` on the host",
				"job_id", jobID,
			)
		} else {
			o.logger.Info("helper container spawned for orchestrator self-replacement",
				"helper_container_id", helperID,
				"delay", selfUpgradeHelperDelay.String(),
				"job_id", jobID,
			)
			// Publish self_upgrade_until for the API/UI so users see a
			// progress banner rather than thinking Apply stalled. TTL-based
			// Valkey key self-cleans without explicit removal, even across
			// orchestrator restarts (the new orchestrator has no record of
			// its prior life's helper spawn, which is exactly what we want —
			// the key just expires).
			expectedCompletion := time.Now().UTC().Add(selfUpgradeHelperDelay + selfUpgradeCompletionSlack)
			ttl := selfUpgradeHelperDelay + selfUpgradeKeyTTLExtra
			setCmd := o.vk.B().Set().Key(selfUpgradeUntilKey).
				Value(expectedCompletion.Format(time.RFC3339)).
				ExSeconds(int64(ttl.Seconds())).Build()
			if vkErr := o.vk.Do(applyCtx, setCmd).Error(); vkErr != nil {
				o.logger.Warn("failed to publish self_upgrade_until to valkey (UX banner will not show; upgrade itself is fine)",
					"error", vkErr, "job_id", jobID)
			}
		}
	}

	return jobID, nil
}

// Rollback reverts to the previous state using the 5-phase rollback sequence
// per Spec D.7. Can be triggered manually or automatically by Apply.
func (o *Orchestrator) Rollback(ctx context.Context) (string, error) {
	return o.RollbackWithJobID(ctx, types.NewUUIDv7())
}

// RollbackWithJobID is like Rollback but uses a pre-generated job ID.
func (o *Orchestrator) RollbackWithJobID(ctx context.Context, jobID string) (string, error) {
	release, err := o.acquireAdvisoryLock(ctx)
	if err != nil {
		return "", fmt.Errorf("orchestrator busy: %w", err)
	}
	defer release()

	if !o.sm.State().CanRollback() {
		return "", &ErrInvalidTransition{From: o.sm.State(), Op: "rollback"}
	}

	// Find the most recent snapshot.
	lastOp, err := o.sm.LastOperation(ctx)
	if err != nil {
		return "", fmt.Errorf("find last operation for rollback: %w", err)
	}

	if lastOp.SnapshotPath == nil || *lastOp.SnapshotPath == "" {
		return "", fmt.Errorf("no snapshot available for rollback")
	}
	snapshotPath := *lastOp.SnapshotPath

	// Record the rollback operation.
	opID, err := o.sm.RecordOperation(ctx, "rollback", "running", lastOp.ConfigHash, nil, lastOp.ContainerVersions)
	if err != nil {
		return "", fmt.Errorf("record rollback operation: %w", err)
	}

	if err := o.sm.Transition(ctx, StateRollingBack); err != nil {
		return "", err
	}

	o.mu.Lock()
	o.lastOp = &Operation{
		JobID:        jobID,
		Type:         "rollback",
		State:        StateRollingBack,
		StartedAt:    time.Now().UTC(),
		SnapshotPath: snapshotPath,
	}
	o.mu.Unlock()

	rollbackCtx, cancel := context.WithTimeout(ctx, o.cfg.RollbackTimeout)
	defer cancel()

	o.logger.Info("starting manual rollback", "job_id", jobID, "snapshot", snapshotPath)

	if err := o.doRollback(rollbackCtx, snapshotPath); err != nil {
		// CRITICAL: rollback itself failed.
		o.logger.Error("CRITICAL: rollback failed, manual intervention required",
			"job_id", jobID,
			"error", err,
		)
		o.sm.SetState(ctx, StateFailed)
		_ = o.sm.CompleteOperation(ctx, opID, "failed", snapshotPath, fmt.Sprintf("CRITICAL: rollback failed: %v", err))

		o.mu.Lock()
		now := time.Now().UTC()
		o.lastOp.State = StateFailed
		o.lastOp.EndedAt = &now
		o.lastOp.Error = err.Error()
		o.mu.Unlock()

		return jobID, fmt.Errorf("CRITICAL: rollback failed: %w", err)
	}

	// Rollback succeeded.
	_ = o.sm.CompleteOperation(ctx, opID, "rolled_back", snapshotPath, "")

	if err := o.sm.Transition(ctx, StateIdle); err != nil {
		return "", fmt.Errorf("transition to idle after rollback: %w", err)
	}

	o.mu.Lock()
	now := time.Now().UTC()
	o.lastOp.State = StateIdle
	o.lastOp.EndedAt = &now
	o.mu.Unlock()

	o.logger.Info("rollback complete", "job_id", jobID)
	return jobID, nil
}

// doRollback executes the internal 5-phase rollback sequence (Spec D.7).
// This is used by both automatic rollback (from Apply) and manual Rollback().
//
// Postgres and valkey stay running throughout — phase 2 (psql restore) needs
// them reachable. If any phase after the stop fails, we make a best-effort
// attempt to restart the services we stopped so the stack doesn't end up half
// down (see Phase 3 E2E findings, 2026-04-18).
func (o *Orchestrator) doRollback(ctx context.Context, snapshotPath string) error {
	// Phase 1: Stop non-data services. Postgres + valkey keep running.
	o.logger.Info("rollback phase 1: stopping services (keeping data services up)")
	stopOrder := NonDataStopOrder()
	if err := o.docker.StopServices(ctx, stopOrder); err != nil {
		return fmt.Errorf("rollback stop services: %w", err)
	}

	// From here on, stopped services must be brought back up even if a
	// subsequent phase fails, or the stack stays partially down.
	recover := func(cause error) error {
		o.logger.Error("rollback phase failed, attempting to restart stopped services",
			"cause", cause,
		)
		if startErr := o.docker.StartServices(ctx, NonDataStartOrder()); startErr != nil {
			o.logger.Error("recovery restart failed — manual intervention required",
				"restart_error", startErr,
			)
			return fmt.Errorf("%w; recovery restart also failed: %v", cause, startErr)
		}
		o.logger.Info("recovery restart succeeded — services back up despite rollback failure")
		return cause
	}

	// Phase 2: Restore database from snapshot.
	o.logger.Info("rollback phase 2: restoring database", "snapshot", snapshotPath)
	if err := o.snap.RestoreSnapshot(ctx, snapshotPath); err != nil {
		return recover(fmt.Errorf("rollback restore database: %w", err))
	}

	// Phase 3: Restore the pre-Apply compose file (if Apply rewrote it), then
	// apply so containers revert to the old image tags. RestoreComposeBackup
	// is a no-op if the backup file doesn't exist — covers both pre-rc30
	// snapshots (no backup file) and the Apply-failed-before-rewrite case.
	//
	// Uses ApplyComposeServices with VectisImageServicesExcludingSelf() rather
	// than ApplyCompose (which touches ALL services incl. orchestrator). Two
	// reasons: (1) rollback never needs to recreate the orchestrator — it's
	// still on its old image throughout any auto-rollback path, since the
	// Phase 7 helper only spawns post-Phase-6-success. (2) ApplyCompose would
	// re-trigger the GA Blocker #9 self-kill if docker chose to recreate the
	// orchestrator for any reason (config drift, half-orphaned state from a
	// failed prior attempt, etc.). The service-list approach sidesteps both.
	o.logger.Info("rollback phase 3: restoring compose backup (if any) and applying")
	if len(o.cfg.ComposePaths) > 0 {
		composePath := o.cfg.ComposePaths[0]
		backupPath := composeBackupPathFor(snapshotPath)
		if err := RestoreComposeBackup(composePath, backupPath); err != nil {
			return recover(fmt.Errorf("rollback restore compose: %w", err))
		}
	}
	// Restore per-service configs that Phase 3.6 may have rewritten. The
	// backup dir is a no-op if Phase 3.6 didn't run (legacy install or
	// no-drift detected) — RestoreConfigsBackup handles missing-dir as
	// success. createdNewFiles is left empty: the rollback path doesn't
	// know which files were brand-new vs replaced, and the safer default
	// is to leave any extra files in place rather than risk deleting a
	// file the operator has since edited. Worst case the next Apply
	// re-evaluates them.
	if len(o.cfg.GeneratedConfigDir) > 0 {
		configBackupDir := configBackupDirFor(snapshotPath)
		if err := RestoreConfigsBackup(o.cfg.GeneratedConfigDir, configBackupDir, nil); err != nil {
			return recover(fmt.Errorf("rollback restore configs: %w", err))
		}
	}
	if err := o.docker.ApplyComposeServices(ctx, VectisImageServicesExcludingSelf()); err != nil {
		return recover(fmt.Errorf("rollback apply compose: %w", err))
	}

	// Phase 4: Start services and health check. Data services already up.
	o.logger.Info("rollback phase 4: starting services and health check")
	if err := o.docker.StartServices(ctx, NonDataStartOrder()); err != nil {
		return fmt.Errorf("rollback health check: %w", err)
	}

	// Phase 5: Complete — handled by the caller.
	o.logger.Info("rollback phase 5: rollback sequence complete")
	return nil
}

// failApply is a helper that transitions to failed state and records the error.
func (o *Orchestrator) failApply(ctx context.Context, opID, jobID, errMsg string) {
	o.logger.Error("apply failed", "job_id", jobID, "error", errMsg)
	o.sm.SetState(ctx, StateFailed)
	_ = o.sm.CompleteOperation(ctx, opID, "failed", "", errMsg)

	o.mu.Lock()
	now := time.Now().UTC()
	if o.lastOp != nil {
		o.lastOp.State = StateFailed
		o.lastOp.EndedAt = &now
		o.lastOp.Error = errMsg
	}
	o.mu.Unlock()
}

// completeRollback records the "rolled_back" history row and returns the
// orchestrator to a usable terminal state after a successful rollback.
//
// Two reasons it does NOT reuse applyCtx (GH #48):
//
//  1. By the time a rollback finishes, applyCtx may already be past its
//     deadline (a slow rollback, or the orchestrator self-update handoff timing
//     out the CLI). A transition issued on an expired context skips the Valkey
//     mirror sync, leaving orchestrator:state stale at "applying"/"rolling_back".
//
//  2. Several Apply rollback paths (Phase 3.5/3.6/4.1/4.2/4.3) never transitioned
//     the in-memory state out of "applying" at all — they only recorded the
//     history row — so the live process stayed wedged in "applying" until a
//     manual orchestrator restart, blocking every subsequent plan/apply with
//     409 STATE_CONFLICT. (Reproduced on the mx1 v0.1.24 canary: the Phase-4.3
//     compose depends_on health gate hard-failed and rolled back, then plan
//     returned STATE_CONFLICT until restart.)
//
// Using a fresh context + SetState (which bypasses transition validation, so it
// lands "idle" from either "applying" or "rolling_back") makes the terminal
// transition always stick: in memory AND in the Valkey mirror.
func (o *Orchestrator) completeRollback(opID, snapshotPath, reason string) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := o.sm.CompleteOperation(ctx, opID, "rolled_back", snapshotPath, reason); err != nil {
		o.logger.Error("failed to record rolled_back history row", "op_id", opID, "error", err)
	}
	// SetState (no transition validation) + fresh ctx so both the in-memory
	// state and the Valkey mirror land on idle regardless of the prior state or
	// the original apply context's deadline.
	o.sm.SetState(ctx, StateIdle)

	o.mu.Lock()
	now := time.Now().UTC()
	if o.lastOp != nil {
		o.lastOp.State = StateIdle
		o.lastOp.EndedAt = &now
		o.lastOp.Error = reason
	}
	o.mu.Unlock()

	o.logger.Info("rollback complete; orchestrator returned to idle", "op_id", opID, "reason", reason)
}

// runMigrations runs pending forward-only database migrations using golang-migrate.
func (o *Orchestrator) runMigrations(ctx context.Context) error {
	o.logger.Info("running database migrations")
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		o.cfg.DBUser, o.cfg.DBPassword, o.cfg.DBHost, o.cfg.DBPort, o.cfg.DBName)

	if err := database.RunMigrations(dsn, o.logger); err != nil {
		return fmt.Errorf("run migrations: %w", err)
	}
	return nil
}

// detectPendingMigrations returns the number of pending migrations by comparing
// the current migration version against the embedded migration files. Returns 0
// if detection fails (non-fatal — plan still works without this information).
func (o *Orchestrator) detectPendingMigrations() int {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		o.cfg.DBUser, o.cfg.DBPassword, o.cfg.DBHost, o.cfg.DBPort, o.cfg.DBName)

	currentVersion, _, err := database.MigrationStatus(dsn)
	if err != nil {
		o.logger.Warn("failed to detect migration status", "error", err)
		return 0
	}

	// Count embedded migration files to determine the latest available version.
	latestVersion := database.LatestMigrationVersion()
	if latestVersion <= currentVersion {
		return 0
	}
	return int(latestVersion - currentVersion)
}
