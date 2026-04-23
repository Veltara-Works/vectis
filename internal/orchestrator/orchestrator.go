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

// Orchestrator is the core state machine that manages system updates.
// It is the only component with Docker socket access and enforces
// serialised execution via Postgres advisory locks per Spec D.
type Orchestrator struct {
	mu     sync.Mutex
	plan   *Plan
	lastOp *Operation

	sm      *StateMachine
	cfg     Config
	db      *pgxpool.Pool
	vk      valkey.Client
	docker  *DockerManager
	snap    *SnapshotManager
	logger  *slog.Logger
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

// Health returns a simple health check response (Spec D.10).
func (o *Orchestrator) Health() HealthResponse {
	state := o.sm.State()
	healthy := state != StateFailed
	return HealthResponse{
		Healthy: healthy,
		State:   state,
	}
}

// acquireAdvisoryLock acquires the Postgres advisory lock for the orchestrator.
// Only one operation can run at a time (Spec D.4).
func (o *Orchestrator) acquireAdvisoryLock(ctx context.Context) error {
	_, err := o.db.Exec(ctx, "SELECT pg_advisory_lock(1)")
	if err != nil {
		return fmt.Errorf("acquire advisory lock: %w", err)
	}
	return nil
}

// releaseAdvisoryLock releases the Postgres advisory lock.
func (o *Orchestrator) releaseAdvisoryLock(ctx context.Context) {
	_, err := o.db.Exec(ctx, "SELECT pg_advisory_unlock(1)")
	if err != nil {
		o.logger.Error("failed to release advisory lock", "error", err)
	}
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
	if err := o.acquireAdvisoryLock(ctx); err != nil {
		return nil, fmt.Errorf("orchestrator busy: %w", err)
	}
	defer o.releaseAdvisoryLock(ctx)

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
	for _, svc := range ServiceStartOrder {
		declared, ok := desired[svc]
		if !ok {
			continue // Not in compose — not orchestrator's concern.
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
	if err := o.acquireAdvisoryLock(ctx); err != nil {
		return "", fmt.Errorf("orchestrator busy: %w", err)
	}
	defer o.releaseAdvisoryLock(ctx)

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
			_ = o.sm.CompleteOperation(applyCtx, opID, "rolled_back", snapshotPath, fmt.Sprintf("migration failed: %v", err))
			return jobID, fmt.Errorf("migration failed, rolled back: %w", err)
		}
	}

	// ===== PHASE 3.5: REWRITE COMPOSE TAGS =====
	//
	// The on-disk compose file was written at install time with whatever
	// release tag was current *then*. Plan's Changes[] carry the target tags
	// from the release channel. If we skipped this step, `docker compose
	// pull` at 4.1 would just re-pull whatever's already in the file — so
	// "Apply v0.1.0-rc29" after a Plan that says "rc28 → rc29" would be a
	// no-op on a box that was installed at rc28. Surfaced end-to-end
	// post-rc27 on sysadmin1001.
	//
	// Any failure here rolls back (DB + compose), same as every other Apply
	// phase. The backup path is derived from snapshotPath so rollback can
	// find it without needing a new persisted field.
	o.logger.Info("phase 3.5: rewriting compose with target tags", "job_id", jobID)

	composePath := ""
	if len(o.cfg.ComposePaths) > 0 {
		composePath = o.cfg.ComposePaths[0]
	}
	if composePath != "" {
		backupPath := composeBackupPathFor(snapshotPath)
		rewritten, rewriteErr := RewriteComposeTags(composePath, plan.Changes, backupPath)
		if rewriteErr != nil {
			o.logger.Error("compose rewrite failed, initiating rollback", "error", rewriteErr)
			rollbackErr := o.doRollback(applyCtx, snapshotPath)
			if rollbackErr != nil {
				o.failApply(applyCtx, opID, jobID, fmt.Sprintf("compose rewrite failed and rollback also failed: rewrite=%v, rollback=%v", rewriteErr, rollbackErr))
				return "", fmt.Errorf("compose rewrite and rollback both failed: %w", rollbackErr)
			}
			_ = o.sm.CompleteOperation(applyCtx, opID, "rolled_back", snapshotPath, fmt.Sprintf("compose rewrite failed: %v", rewriteErr))
			return jobID, fmt.Errorf("compose rewrite failed, rolled back: %w", rewriteErr)
		}
		if rewritten {
			o.logger.Info("compose rewritten with target tags",
				"job_id", jobID,
				"backup", backupPath,
				"change_count", len(plan.Changes),
			)
		} else {
			o.logger.Info("compose needed no rewrite (tags already match plan)", "job_id", jobID)
		}
	}

	// ===== PHASE 4: UPDATE CONTAINERS =====
	o.logger.Info("phase 4: updating containers", "job_id", jobID)

	// 4.1 Pull new images.
	if err := o.docker.PullImages(applyCtx, ServiceStartOrder); err != nil {
		o.logger.Error("image pull failed, initiating rollback", "error", err)
		rollbackErr := o.doRollback(applyCtx, snapshotPath)
		if rollbackErr != nil {
			o.failApply(applyCtx, opID, jobID, fmt.Sprintf("pull failed and rollback also failed: pull=%v, rollback=%v", err, rollbackErr))
			return "", fmt.Errorf("pull and rollback both failed: %w", rollbackErr)
		}
		_ = o.sm.CompleteOperation(applyCtx, opID, "rolled_back", snapshotPath, fmt.Sprintf("image pull failed: %v", err))
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
		_ = o.sm.CompleteOperation(applyCtx, opID, "rolled_back", snapshotPath, fmt.Sprintf("stop services failed: %v", err))
		return jobID, fmt.Errorf("stop services failed, rolled back: %w", err)
	}

	// 4.3 Apply new docker-compose.yml.
	if err := o.docker.ApplyCompose(applyCtx); err != nil {
		o.logger.Error("apply compose failed, initiating rollback", "error", err)
		rollbackErr := o.doRollback(applyCtx, snapshotPath)
		if rollbackErr != nil {
			o.failApply(applyCtx, opID, jobID, fmt.Sprintf("compose apply failed and rollback also failed: compose=%v, rollback=%v", err, rollbackErr))
			return "", fmt.Errorf("compose apply and rollback both failed: %w", rollbackErr)
		}
		_ = o.sm.CompleteOperation(applyCtx, opID, "rolled_back", snapshotPath, fmt.Sprintf("compose apply failed: %v", err))
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
		_ = o.sm.CompleteOperation(applyCtx, opID, "rolled_back", snapshotPath, fmt.Sprintf("health check failed: %v", err))
		_ = o.sm.Transition(applyCtx, StateIdle)
		return jobID, fmt.Errorf("health check failed, rolled back: %w", err)
	}

	// ===== PHASE 6: COMPLETE =====
	o.logger.Info("phase 6: completing apply", "job_id", jobID)

	_ = o.sm.CompleteOperation(applyCtx, opID, "completed", snapshotPath, "")

	if err := o.sm.Transition(applyCtx, StateIdle); err != nil {
		return "", fmt.Errorf("transition to idle after apply: %w", err)
	}

	o.mu.Lock()
	o.plan = nil // Plan consumed.
	now := time.Now().UTC()
	o.lastOp.State = StateIdle
	o.lastOp.EndedAt = &now
	o.mu.Unlock()

	o.logger.Info("apply complete", "job_id", jobID)
	return jobID, nil
}

// Rollback reverts to the previous state using the 5-phase rollback sequence
// per Spec D.7. Can be triggered manually or automatically by Apply.
func (o *Orchestrator) Rollback(ctx context.Context) (string, error) {
	return o.RollbackWithJobID(ctx, types.NewUUIDv7())
}

// RollbackWithJobID is like Rollback but uses a pre-generated job ID.
func (o *Orchestrator) RollbackWithJobID(ctx context.Context, jobID string) (string, error) {
	if err := o.acquireAdvisoryLock(ctx); err != nil {
		return "", fmt.Errorf("orchestrator busy: %w", err)
	}
	defer o.releaseAdvisoryLock(ctx)

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
	o.logger.Info("rollback phase 3: restoring compose backup (if any) and applying")
	if len(o.cfg.ComposePaths) > 0 {
		composePath := o.cfg.ComposePaths[0]
		backupPath := composeBackupPathFor(snapshotPath)
		if err := RestoreComposeBackup(composePath, backupPath); err != nil {
			return recover(fmt.Errorf("rollback restore compose: %w", err))
		}
	}
	if err := o.docker.ApplyCompose(ctx); err != nil {
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
