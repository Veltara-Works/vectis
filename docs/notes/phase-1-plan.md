# Vectis Phase 1 — Implementation Plan

**Date:** 2026-03-29
**Branch:** `feature/phase-1` (from `main` at Phase 0.5 complete)
**Merge to main:** When Phase 1 is complete, tested, and audited

---

## Scope Summary

Phase 1 adds six major components to the Phase 0.5 baseline:

| # | Component | Complexity | Dependencies |
|---|-----------|-----------|--------------|
| 1 | **Orchestrator** | High | None (standalone) |
| 2 | **Backup/Restore** | Medium | Orchestrator (snapshot mechanism) |
| 3 | **ValidonX Licensing** | Medium | ValidonX APIs ready (confirmed ✓) |
| 4 | **Full Admin UI** | Medium | Orchestrator + Backup APIs |
| 5 | **Monitoring/Alerts** | Low-Medium | Config engine (alert config) |
| 6 | **Deliverability Dashboard** | Low | DNS checking (exists in Phase 0.5) |

---

## Build Order (dependency-driven)

### Sprint 1: Orchestrator Core
The orchestrator is the foundation — backup, updates, and admin UI all depend on it.

**1.1 Orchestrator container + internal HTTP API**
- New Go service in `internal/orchestrator/`
- State machine: idle → planning → validating → applying → rolling_back → failed → completed
- Postgres advisory lock for concurrency control
- Bearer token authentication from secrets.yaml
- Docker socket access (the ONLY container with this privilege per ADR-017)
- Internal HTTP endpoints: POST /internal/plan, /internal/apply, /internal/rollback, GET /internal/status, /internal/health

**1.2 Snapshot mechanism**
- Pre-apply `pg_dump` to `/var/vectis/snapshots/pre-update-{timestamp}.sql`
- Record container versions in `orchestrator_history` table
- Restore = `psql < snapshot.sql` + revert container tags

**1.3 Apply sequence**
- 6-phase pipeline: validate → snapshot → migrate → update containers → health check → complete
- Service stop/start in dependency order
- Per-service health check timeouts (15s–180s)
- Auto-rollback on health check failure

**1.4 Crash recovery**
- On restart: check `orchestrator_history` for orphaned `running` status → set to `failed`
- Advisory lock auto-releases on connection drop

**1.5 Self-update CLI**
- `vectis update self` — bypasses orchestrator, runs on host
- Pulls new orchestrator + API images, stops/starts, health checks, reverts on failure

**1.6 API proxy endpoints**
- Wire public orchestrator endpoints (Spec A.6) to internal HTTP API
- POST /api/v1/orchestrator/plan, /apply, /rollback
- GET /api/v1/orchestrator/status, /history

**1.7 CLI commands**
- `vectis update plan` — generate update plan
- `vectis update apply` — execute plan (requires prior plan or --force)
- `vectis update rollback` — rollback to last snapshot
- `vectis update self` — self-update flow

### Sprint 2: Backup/Restore
Depends on orchestrator snapshot mechanism.

**2.1 Backup create**
- `vectis backup create` CLI + `POST /api/v1/backup/create` API
- Async job: pg_dump + mail data (rsync Maildir) + config + DKIM keys
- Archive to `/var/vectis/backups/vectis-YYYYMMDD-HHMMSS.tar.gz`
- Progress reporting via job ID polling

**2.2 Backup restore**
- `vectis backup restore` CLI + `POST /api/v1/backup/restore/:id` API
- Requires `--confirm` flag / `X-Confirm-Restore: true` header
- Stops all services, replaces all data, restarts, health checks

**2.3 Backup list + status**
- `GET /api/v1/backup/list` — timestamps, sizes, completeness
- `GET /api/v1/backup/status/:jobId` — progress for running backup

**2.4 Scheduled backups**
- Config in config.yaml: `backup.enabled`, `backup.schedule` (cron), `backup.retain_days`
- Background goroutine or cron-triggered job

### Sprint 3: ValidonX Integration
Depends on ValidonX APIs (confirmed ready per readiness checklist).

**3.1 ValidonX client library**
- New package `internal/validonx/`
- HTTP client for ValidonX API calls
- Authentication: POST /v1/auth/login → cache service token
- Tenant resolution: GET /v1/tenants/{id}
- Subscription check: GET /v1/subscriptions/{id}
- License resolve: POST /v1/licensing/resolve
- Billing event logging: POST /v1/billing/events
- 30-day grace period when ValidonX is unreachable (cached entitlements)

**3.2 Feature gating middleware**
- Middleware that checks license for Pro/Enterprise features
- Free tier: basic mail stack (unlimited in Phase 0.5, gated in Phase 1)
- Pro tier: custom branding, priority support, private GHCR images
- Enterprise tier: multi-tenant, advanced deliverability, SLA

**3.3 ValidonX agent container**
- Optional sidecar container on `vectis-data` network (per Spec G.3)
- Stores cached entitlements in Postgres
- Periodic license check + billing event flush

**3.4 Stripe state mapping**
- Respect subscription states: active, trialing, paused, scheduled_for_cancellation, canceled
- Grace periods for paused/cancellation states
- Error handling per ValidonX error taxonomy (BILLING.SUBSCRIPTION_*, BILLING.LICENSING_*, BILLING.AUTH_*)

### Sprint 4: Full Admin UI
Depends on orchestrator + backup APIs being available.

**4.1 Admin management**
- List, create, edit, delete admin accounts
- Role display (admin only in Phase 1; domain_admin in Phase 2)

**4.2 Audit log viewer**
- Table view of `audit_log` entries
- Filter by admin, resource type, action, date range
- Paginated with existing cursor mechanism

**4.3 Orchestrator controls**
- "Plan Update" button → shows diff
- "Apply Update" button → progress display
- "Rollback" button → confirmation dialog
- Status indicator showing current orchestrator state
- History table of past operations

**4.4 Backup controls**
- "Create Backup" button → progress indicator
- Backup list with timestamps, sizes
- "Restore" button with confirmation

**4.5 Session management UI**
- View all active sessions (already exists in API)
- Revoke individual sessions
- "Revoke all other sessions" button

### Sprint 5: Monitoring & Alerts
Lower dependency — can be built in parallel with Sprint 4.

**5.1 Alert configuration**
- Config in config.yaml: `alerts.email.enabled`, `alerts.email.recipients`, `alerts.webhook.enabled`, `alerts.webhook.url`
- Alert on: service unhealthy, disk full, cert expiring, queue growing, rollback failure

**5.2 Alert dispatcher**
- Email alerts via local Postfix (no external SMTP needed)
- Webhook alerts: POST JSON payload to configured URL
- Deduplication: same alert not sent more than once per 15 minutes
- CRITICAL alerts bypass deduplication

**5.3 Health monitor**
- Background goroutine checking service health periodically
- Disk usage monitoring for `/var/vectis/mail` and Postgres
- Mail queue length monitoring
- TLS certificate expiry monitoring

### Sprint 6: Deliverability Dashboard
Lowest priority — builds on existing Phase 0.5 deliverability check.

**6.1 Deliverability dashboard page**
- Per-domain deliverability scores
- SPF/DKIM/DMARC/PTR status with auto-refresh
- Recommendations for improving deliverability
- History of deliverability changes

---

## Database Migrations Needed

Phase 1 requires a new migration (`000002_phase1.up.sql`):

1. **No new tables needed** — `orchestrator_history` already exists from Phase 0.5 schema
2. **Possible additions:**
   - `admin_recovery_email` column on `admins` table (for Phase 1 password recovery)
   - `backup_jobs` table (for async backup tracking)
   - `alert_history` table (for alert deduplication)
   - `validonx_cache` table (for cached license entitlements)

---

## New Docker Container

**Orchestrator container:**
- Dockerfile: `docker/orchestrator/Dockerfile`
- Image: `ghcr.io/veltara-works/vectis-orchestrator:latest`
- Network: `vectis-orchestrator` only
- Volumes: `/var/run/docker.sock:/var/run/docker.sock:ro` (the ONLY container with Docker socket)
- Environment: bearer token from secrets.yaml

---

## Estimated Timeline

| Sprint | Duration | Can Parallelize |
|--------|----------|----------------|
| 1: Orchestrator | 3-4 sessions | No (foundation) |
| 2: Backup | 1-2 sessions | After Sprint 1 |
| 3: ValidonX | 2-3 sessions | After Sprint 1 |
| 4: Admin UI | 2-3 sessions | After Sprints 1+2 |
| 5: Monitoring | 1-2 sessions | After Sprint 1 |
| 6: Deliverability | 1 session | Any time |

Sprints 2, 3, and 5 can run in parallel once Sprint 1 (Orchestrator) is done.

---

## Merge Criteria

Phase 1 merges to `main` when:
- [ ] All 6 sprints complete
- [ ] Full compliance audit passes (same format as Phase 0.5)
- [ ] Integration tests pass
- [ ] End-to-end update/rollback cycle tested
- [ ] Backup create/restore tested
- [ ] ValidonX license check tested (or stubbed if ValidonX API not available)
- [ ] All admin UI pages functional
- [ ] No regressions in Phase 0.5 functionality
