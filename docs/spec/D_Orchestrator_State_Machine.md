# D. Orchestrator State Machine

**Status:** DRAFT — For review with Copilot before integration into Spec v1.1  
**Prepared by:** Claude (round 5)  
**Complements:** Vectis Architecture v1.3, Implementation Spec v1.0

---

## D.1 Overview

The orchestrator is a stateful component with well-defined states and transitions. It is the only component with Docker socket access, and it enforces serialised execution — only one operation can be active at a time.

The orchestrator exposes an internal HTTP API (bearer token authenticated, internal network only) consumed by the Go API. It persists its state to both Valkey (for fast queries) and Postgres (for persistence across restarts).

---

## D.2 States

| State | Description | API Accepts |
|-------|-------------|-------------|
| `idle` | No operation in progress. System is stable. | plan, apply (if plan exists), rollback |
| `planning` | Computing diff between current and desired state. | status only |
| `validating` | Running validation checks on planned changes. | status only |
| `applying` | Executing the update plan (snapshot → migrate → pull → restart → health check). | status only |
| `rolling_back` | Reverting to previous state after failure or manual trigger. | status only |
| `failed` | Last operation failed. System may be in inconsistent state. | rollback, plan |
| `completed` | Last operation completed successfully. Transitions to idle automatically. | plan, apply, rollback |

---

## D.3 State Transitions

All transitions not listed below are rejected with `HTTP 409 Conflict`.

| From | To | Trigger | Notes |
|------|----|---------|-------|
| `idle` | `planning` | `POST /plan` | Orchestrator computes diff |
| `planning` | `idle` | Plan computation completes | Plan stored in memory and Postgres |
| `planning` | `failed` | Plan computation error | e.g., cannot reach Docker, cannot connect to registry |
| `idle` | `validating` | `POST /apply` | Requires a stored plan; begins validation |
| `validating` | `applying` | All validation checks pass | Automatic transition |
| `validating` | `failed` | Validation fails | Plan rejected; no changes made to system |
| `applying` | `idle` | All health checks pass post-update | Update successful; history recorded |
| `applying` | `rolling_back` | Health check failure or timeout | Automatic rollback triggered |
| `applying` | `failed` | Error before snapshot taken | Nothing to rollback; e.g., image pull fails before any state change |
| `idle` | `rolling_back` | `POST /rollback` | Manual rollback request |
| `failed` | `rolling_back` | `POST /rollback` | Recovery from failed state |
| `rolling_back` | `idle` | Rollback succeeds | System restored to previous state |
| `rolling_back` | `failed` | Rollback fails | **CRITICAL:** Manual intervention required |

### Transition diagram (text representation)

```
                    ┌────────────┐
          ┌────────>│    idle    │<──────────────┐
          │         └─────┬──┬──┘               │
          │          plan │  │ apply        rollback
          │               │  │              succeeds
          │               v  │                  │
          │         ┌─────────┐           ┌─────┴──────┐
     plan │         │planning │           │rolling_back│
  completes         └────┬────┘           └─────┬──────┘
          │              │                      │
          │         error│               rollback│fails
          │              │                      │
          │              v                      v
          │         ┌────────┐            ┌────────┐
          └─────────│ failed │<───────────│ failed │
                    └────┬───┘            └────────┘
                         │
                    rollback
                         │
                         v
                    ┌──────────┐
             ┌─────│validating│
             │     └─────┬────┘
             │           │ passes
        fails│           v
             │     ┌──────────┐
             │     │ applying  │
             │     └──┬────┬──┘
             │        │    │
             │   health│  health
             │   check │  check
             │   fails │  passes
             │        │    │
             v        v    v
          failed   rolling  idle
                    _back
```

---

## D.4 Concurrency Control

### Locking mechanism

The orchestrator uses a Postgres advisory lock to ensure mutual exclusion:

```go
// At the start of any operation
_, err := db.Exec("SELECT pg_advisory_lock(1)")  // lock ID 1 = orchestrator
if err != nil {
    return ErrOrchestratorBusy
}
defer db.Exec("SELECT pg_advisory_unlock(1)")
```

### Behaviour under contention

- If a second request arrives while an operation is active, the Go API (not the orchestrator) checks the current state in Valkey and returns `409 Conflict` immediately — it doesn't even forward the request to the orchestrator.
- The `409` response includes the current state and operation start time so the admin can monitor progress.

### Crash recovery

- If the orchestrator process crashes mid-operation, the Postgres connection drops, which automatically releases the advisory lock.
- On restart, the orchestrator checks `orchestrator_history` for the last operation:
  - If `status = running` → set to `failed`, enter `failed` state
  - If `status = completed` → enter `idle`
  - If `status = failed` → remain in `failed`
- The admin can then decide whether to rollback or re-attempt.

---

## D.5 Timeout Configuration

| Operation | Default Timeout | Configurable | Notes |
|-----------|----------------|--------------|-------|
| Image pull (per image) | 300s | Yes (config.yaml) | ClamAV image is ~1 GB, needs longer on slow connections |
| Container health check | 120s | Yes, per service | ClamAV needs longer startup (signature loading) |
| DB migration (total) | 60s | No | Should be fast; failure triggers rollback |
| Full apply cycle | 600s | Yes (config.yaml) | Overall timeout for the entire apply operation |
| Rollback (total) | 300s | No | Must complete; no timeout-triggered abort |

### Per-service health check timeouts

| Service | Default Health Timeout | Rationale |
|---------|----------------------|-----------|
| Postfix | 30s | Fast startup |
| Dovecot | 30s | Fast startup |
| Rspamd | 60s | Loads rules and models |
| ClamAV | 180s | Loads virus signature database (~1–2 GB in memory) |
| Postgres | 30s | Fast startup |
| Valkey | 15s | Very fast startup |
| Go API | 30s | Depends on Postgres + Valkey being healthy first |
| Admin UI | 15s | Static file serving |

These timeouts are used by the orchestrator to determine how long to wait for Docker's HEALTHCHECK to report `healthy` after a container restart.

---

## D.6 Apply Sequence (Detailed)

When `POST /apply` is called, the orchestrator executes this sequence:

```
1. VALIDATE
   1.1  Verify stored plan exists and is not stale
   1.2  Validate config.yaml syntax (JSON Schema)
   1.3  Validate config.yaml semantics (domain format, port ranges, etc.)
   1.4  Dry-run DB migrations (if supported by migration tool)
   1.5  Verify required container images are available in registry
   1.6  Verify disk space is sufficient (images + snapshot)
   1.7  Optional: verify DNS readiness (DKIM/SPF/DMARC records)
   → If any validation fails: set state = failed, return errors

2. SNAPSHOT
   2.1  Run pg_dump of Vectis database → /var/vectis/snapshots/pre-update-{timestamp}.sql
   2.2  Record current container versions in orchestrator_history
   2.3  Record current config hash
   → If snapshot fails: set state = failed (no changes made yet)

3. MIGRATE
   3.1  Apply forward-only DB migrations in order
   → If migration fails: restore from snapshot (step 2.1), set state = rolling_back → idle

4. UPDATE CONTAINERS
   4.1  Pull new container images (in parallel where possible)
   4.2  Stop services in reverse dependency order:
        Admin UI → Go API → Rspamd → ClamAV → Dovecot → Postfix → Valkey → Postgres
   4.3  Apply new docker-compose.yml (generated by config engine)
   4.4  Start services in dependency order:
        Postgres → Valkey → Postfix → Dovecot → Rspamd → ClamAV → Go API → Admin UI
   → If pull fails: set state = failed (DB already migrated → attempt rollback)
   → If start fails: attempt rollback

5. HEALTH CHECK
   5.1  Wait for each container's Docker HEALTHCHECK to report healthy
   5.2  Use per-service timeouts (see D.5)
   5.3  Check services in dependency order
   → If any service fails health check: trigger full rollback

6. COMPLETE
   6.1  Update orchestrator_history: status = completed
   6.2  Set state = idle
   6.3  Report success to API
```

### Service dependency order

The start/stop order matters because services depend on each other:

```
Postgres ─── Valkey ─── Postfix ─── Dovecot
                │         │
                │         └── Rspamd ─── ClamAV
                │
                └── Go API ─── Admin UI
```

Start order: left to right (dependencies first).  
Stop order: right to left (dependents first).

---

## D.7 Rollback Sequence (Detailed)

Rollback is triggered either automatically (health check failure) or manually (`POST /rollback`).

```
1. STOP CURRENT CONTAINERS
   1.1  Stop all Vectis containers (reverse dependency order)

2. RESTORE DATABASE
   2.1  Drop current database
   2.2  Restore from snapshot: psql < /var/vectis/snapshots/pre-update-{timestamp}.sql
   → If restore fails: set state = failed (CRITICAL — manual intervention required)

3. REVERT CONTAINERS
   3.1  Apply previous docker-compose.yml (with previous image tags from orchestrator_history)
   3.2  Start containers in dependency order

4. HEALTH CHECK
   4.1  Wait for all health checks to pass
   → If health checks fail after rollback: set state = failed (CRITICAL)

5. COMPLETE
   5.1  Update orchestrator_history: status = rolled_back
   5.2  Set state = idle
   5.3  Report rollback result to API
```

### Critical failure: rollback fails

If rollback itself fails (step 2.2 or 4.1), the system enters the `failed` state with no automated recovery path. The orchestrator:

1. Logs detailed error information
2. Sends alert (email/webhook) with subject "CRITICAL: Vectis rollback failed — manual intervention required"
3. Remains in `failed` state
4. The admin must follow the manual recovery procedure documented in `docs/recovery.md`

Manual recovery procedure (referenced, documented separately):
1. Access the server via SSH
2. Manually restore database: `psql -U postgres vectis < /var/vectis/snapshots/<snapshot_file>`
3. Manually revert docker-compose.yml to previous version
4. Run `docker compose up -d`
5. Verify services with `vectis health`
6. If all else fails, restore from last known good backup: `vectis backup restore <backup_file> --confirm`

---

## D.8 Orchestrator Self-Update

The orchestrator cannot restart itself. Self-updates are a special case handled by the CLI on the host:

### Flow

```
1. vectis update self
2. CLI checks registry for new orchestrator + API images
3. CLI pulls new images
4. CLI stops orchestrator container
5. CLI stops API container
6. CLI updates docker-compose.yml with new image tags (for orchestrator + API only)
7. CLI starts new orchestrator container
8. CLI starts new API container
9. CLI runs health checks on both
10. If health checks fail:
    - CLI reverts docker-compose.yml to previous tags
    - CLI restarts previous images
    - CLI reports failure
11. If health checks pass:
    - CLI reports success
```

This is the **only operation** that bypasses the orchestrator's state machine. It is implemented entirely in the CLI binary running on the host (not inside any container).

---

## D.9 Plan Staleness

A stored plan can become stale if the system state changes between `plan` and `apply`. The orchestrator checks for staleness at the start of `apply`:

- Compare current config.yaml hash against the plan's recorded hash
- Compare current container versions against the plan's baseline versions
- If either has changed, reject the apply with `PLAN_STALE` error and require a new plan

This prevents applying an update plan that was computed against a different system state.

---

## D.10 Orchestrator Internal API

The orchestrator exposes these internal HTTP endpoints (Docker internal network only, bearer token authenticated):

| Method | Endpoint | Request Body | Response |
|--------|----------|-------------|----------|
| POST | /internal/plan | `{}` | `{ plan: {...}, state: "idle" }` |
| POST | /internal/apply | `{}` | `{ job_id: "uuid", state: "validating" }` |
| POST | /internal/rollback | `{}` | `{ job_id: "uuid", state: "rolling_back" }` |
| GET | /internal/status | — | `{ state: "idle", last_operation: {...} }` |
| GET | /internal/health | — | `{ healthy: true }` |

All responses include the current state machine state. The Go API maps these to the public API endpoints documented in Section A.
