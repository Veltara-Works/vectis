# A. API Endpoint Inventory

**Status:** Living reference — kept in sync with `internal/api/server.go`
**Last refreshed:** 2026-05-17 (against `main`)
**Complements:** Vectis Architecture v1.4 (frozen), Implementation Spec v1.1
**Source of truth:** Route registrations in [`internal/api/server.go`](../../internal/api/server.go) — refresh this doc whenever a new route is added.

---

## A.1 Overview

All endpoints are prefixed with `/api/v1`. Authentication is required for all endpoints except those listed in [A.2](#a2-public-no-auth).

All responses use a consistent JSON envelope:

```json
{
  "data": { ... },
  "error": null,
  "meta": {
    "request_id": "uuid",
    "timestamp": "2026-04-27T12:00:00Z"
  }
}
```

Error responses:

```json
{
  "data": null,
  "error": {
    "code": "DOMAIN_EXISTS",
    "message": "Domain example.com already exists",
    "details": { ... }
  },
  "meta": { ... }
}
```

Auth column legend used throughout: `none` = public; `session` = signed admin session cookie; `api-key` = `X-API-Key` header (sending API + storage); `admin+` = role ≥ admin (i.e. admin or super_admin); `super` = super_admin only.

---

## A.2 Public (no auth)

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/health | System health summary | none |
| GET | /api/v1/version | Vectis version + per-container image tags | none |
| GET | /api/v1/metrics/prometheus | Prometheus scrape endpoint (collector registered in `internal/metrics`) | super_admin |
| POST | /api/v1/auth/login | Authenticate admin, return session cookie | none |
| POST | /api/v1/auth/reset-request | Request password-reset email | none |
| POST | /api/v1/auth/reset-password | Complete password reset with token | none |
| GET | /api/v1/auth/oidc/providers | List enabled OIDC providers (suppressed to `[]` on Free) | none |
| GET | /api/v1/auth/oidc/login/{provider} | Begin OIDC SSO redirect | none, gated by `oidc_sso` (browser-friendly 402+HTML on Free) |
| GET | /api/v1/auth/oidc/callback/{provider} | OIDC SSO callback | none, gated by `oidc_sso` |
| GET | /api/v1/auth/saml/providers | List enabled SAML providers (suppressed to `[]` unless Enterprise) | none |
| GET | /api/v1/auth/saml/metadata/{provider} | SP metadata XML for the IdP (no secrets) | none |
| GET | /api/v1/auth/saml/login/{provider} | Begin SP-initiated SAML SSO redirect | none, gated by `saml_sso` (browser-friendly 402+HTML on non-Enterprise) |
| POST | /api/v1/auth/saml/acs/{provider} | SAML Assertion Consumer Service (HTTP-POST binding) | none, gated by `saml_sso`; authenticity = signed assertion + RelayState |
| POST | /api/v1/internal/inbound | Postfix → API inbound webhook delivery | localhost-only via socket |
| GET | /api/v1/track/open/{token} | Open-tracking pixel | none |
| GET | /api/v1/track/click/{token} | Click-tracking redirect | none |

---

## A.3 Authenticated session — auth + TOTP + sessions

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/auth/me | Current admin profile | session |
| POST | /api/v1/auth/logout | Invalidate current session | session |
| POST | /api/v1/auth/logout-all | Invalidate all sessions for current admin | session |
| GET | /api/v1/auth/sessions | List active sessions for current admin | session |
| DELETE | /api/v1/auth/sessions/{sessionID} | Invalidate a specific session | session |
| POST | /api/v1/auth/totp/setup | Begin TOTP enrolment (returns QR URI) | session |
| POST | /api/v1/auth/totp/verify | Confirm TOTP enrolment with first code | session |
| DELETE | /api/v1/auth/totp | Remove TOTP (requires current TOTP code) | session |
| DELETE | /api/v1/auth/oidc/disconnect | Unlink OIDC provider from admin | session |
| POST | /api/v1/auth/saml/disconnect | Unlink SAML provider from admin (refused if no password set) | session |

### Login flow

1. Client sends `POST /auth/login` with `{ email, password }`
2. If TOTP is enabled for the admin, API returns `{ requires_totp: true, totp_session: "temp_token" }`
3. Client sends `POST /auth/login` with `{ totp_session, totp_code }`
4. On success, API sets a signed session cookie and returns admin profile

### Session management

- Sessions stored in both Valkey (fast auth lookup) and Postgres (session inventory/revocation UI)
- Valkey is the authority for session validity
- Postgres is the authority for session inventory
- Session cookie: `HttpOnly`, `Secure`, `SameSite=Strict`
- Session expiry: configurable, default 24 hours
- Session token: 256-bit random, stored as SHA-256 hash in Postgres

---

## A.4 Domains

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/domains | List domains | session (domain_admin scoped in handler) |
| GET | /api/v1/domains/{domainID} | Get domain details | session |
| GET | /api/v1/domains/{domainID}/dkim | DKIM public key as DNS TXT record | session |
| GET | /api/v1/domains/{domainID}/deliverability | Run SPF/DKIM/DMARC/PTR/TLS checks | session |
| POST | /api/v1/domains | Create domain (triggers DKIM keygen) | admin+ |
| PATCH | /api/v1/domains/{domainID} | Update domain settings | admin+ |
| DELETE | /api/v1/domains/{domainID} | Remove domain (409 if mailboxes/aliases exist) | admin+ |
| POST | /api/v1/domains/{domainID}/dkim/generate | Generate new DKIM key pair | admin+ |
| POST | /api/v1/domains/{domainID}/dkim/rotate | Rotate DKIM key with new selector | admin+ |
| POST | /api/v1/domains/{domainID}/verify | Re-run DNS/PTR verification | admin+ |
| GET | /api/v1/domains/{domainID}/spam-lists | List per-domain allow/block list entries | admin+, gated by `advanced_spam` |
| POST | /api/v1/domains/{domainID}/spam-lists | Add an allow/block list entry | admin+, gated by `advanced_spam` |
| DELETE | /api/v1/domains/{domainID}/spam-lists/{entryID} | Remove an allow/block list entry | admin+, gated by `advanced_spam` |

Spam-list field-level extensions to `PATCH /domains/{domainID}` (e.g. `reject_threshold`, `greylist_enabled`) are gated inside the handler — the core domain CRUD route stays open to Free for ungated fields like `spam_threshold`. See [`internal/api/handle_domains.go`].

### Domain creation flow

1. `POST /domains` with `{ name: "example.com" }`
2. API validates domain name format
3. API inserts domain into Postgres
4. API generates DKIM key pair (RSA-2048; see Section C)
5. API stores private key in `/var/vectis/dkim/<domain>/`
6. API triggers Rspamd config reload (DKIM signing config)
7. API returns domain object + DKIM DNS record to display
8. Postfix and Dovecot pick up the new domain via live SQL lookup — no reload needed

### Domain deletion constraints

- Cannot delete a domain that has mailboxes (409 with count)
- Cannot delete a domain that has aliases (409 with count)
- Admin must explicitly delete all mailboxes and aliases first

---

## A.5 Mailboxes + Sieve + impersonation

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/mailboxes | List mailboxes | session (domain_admin scoped) |
| POST | /api/v1/mailboxes | Create mailbox (Argon2id password hash) | session |
| GET | /api/v1/mailboxes/{mailboxID} | Get mailbox details | session |
| PATCH | /api/v1/mailboxes/{mailboxID} | Update mailbox (quota / password / display / active) | session |
| DELETE | /api/v1/mailboxes/{mailboxID} | Delete mailbox (`X-Confirm-Delete: true`) | session |
| GET | /api/v1/mailboxes/{mailboxID}/sieve | List Sieve scripts for mailbox | session |
| GET | /api/v1/mailboxes/{mailboxID}/sieve/{scriptName} | Get one Sieve script | session |
| PUT | /api/v1/mailboxes/{mailboxID}/sieve | Upsert Sieve script | session |
| DELETE | /api/v1/mailboxes/{mailboxID}/sieve/{scriptName} | Delete Sieve script | session |
| POST | /api/v1/mailboxes/{mailboxID}/impersonate | Begin admin impersonation of mailbox | admin+ |
| DELETE | /api/v1/mailboxes/{mailboxID}/impersonate | End impersonation | admin+ |

### Mailbox creation flow

1. `POST /mailboxes` with `{ domain_id, local_part, password, quota_mb?, display_name? }`
2. API validates domain exists and is active
3. API validates `local_part` uniqueness within domain
4. API hashes password with Argon2id
5. API inserts mailbox into Postgres
6. API creates Maildir: `/var/vectis/mail/<domain>/<local_part>/Maildir/{cur,new,tmp}`
7. Postfix and Dovecot pick up via live SQL lookup — no reload needed

### Mailbox deletion

- Requires `X-Confirm-Delete: true` header
- Optional body `{ archive: true }` copies Maildir to `/var/vectis/archives/<domain>/<local_part>-<timestamp>/`
- Removes from Postgres, then removes Maildir (unless archived)

### Free-tier caps (Pro lifts)

- Free: max 3 domains; max 25 mailboxes per domain (enforced in `handleCreateDomain` / `handleCreateMailbox`).
- Pro: unlimited.
- Existing resources are NOT retroactively suspended on Pro→Free downgrade — only new creations past the cap are blocked.

---

## A.6 Aliases

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/aliases | List aliases | session (domain_admin scoped) |
| POST | /api/v1/aliases | Create alias | session |
| GET | /api/v1/aliases/{aliasID} | Get alias details | session |
| PATCH | /api/v1/aliases/{aliasID} | Update alias destination(s) / active | session |
| DELETE | /api/v1/aliases/{aliasID} | Delete alias | session |

- `source_local_part` may be the empty string for catch-all aliases
- `destination` may be a single address or comma-separated list
- Aliases take effect immediately via Postfix SQL lookup — no reload needed

---

## A.7 Admins

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/admins | List admins | session |
| POST | /api/v1/admins | Create admin | super |
| PATCH | /api/v1/admins/{adminID} | Update admin (email / role / password / TOTP-confirm) | super |
| DELETE | /api/v1/admins/{adminID} | Delete admin | super |

The Edit modal handles email + role + password + (when actor has TOTP enabled) a TOTP code in a single PATCH. There is no separate password-reset endpoint for admins — super_admin sets new password directly.

---

## A.8 Sending API + Storage

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| POST | /api/v1/send | Send a single message | session or api-key |
| POST | /api/v1/send/batch | Send a batch of messages | session or api-key |
| GET | /api/v1/messages | List messages (storage API) | session or api-key |
| GET | /api/v1/messages/{messageID} | Get one message + delivery state | session or api-key |
| GET | /api/v1/api-keys | List API keys | session |
| POST | /api/v1/api-keys | Create API key | session |
| DELETE | /api/v1/api-keys/{keyID} | Revoke API key | session |

Domain scoping: handlers enforce that a session/api-key may only act on domains within the actor's authorised set.

---

## A.9 Webhooks + Audit + Engagement tracking

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/webhooks | List webhook subscriptions | admin+ |
| POST | /api/v1/webhooks | Create webhook subscription | admin+ |
| DELETE | /api/v1/webhooks/{webhookID} | Delete webhook subscription | admin+ |
| GET | /api/v1/audit | List audit-log entries (platform-wide; handler returns unfiltered) | super |
| GET | /api/v1/audit/export | Export audit log (CSV) | super |
| GET | /api/v1/tracking/stats | Aggregate engagement stats | admin+ & Pro (FeatureAnalytics) |
| GET | /api/v1/tracking/messages/{messageID} | Per-message engagement summary | admin+ & Pro (FeatureAnalytics) |
| GET | /api/v1/tracking/messages/{messageID}/events | Per-message engagement event stream | admin+ & Pro (FeatureAnalytics) |

Webhook events emitted: `mail.queued`, `mail.delivered`, `mail.bounced`, `mail.deferred`, `mail.complained`, `mail.opened`, `mail.clicked` (all 7 firing on prod since 2026-04-19).

---

## A.10 Abuse / suspension

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/abuse/dashboard | Abuse-detection summary | admin+ |
| GET | /api/v1/abuse/events | List abuse events | admin+ |
| POST | /api/v1/abuse/events/{eventID}/resolve | Mark abuse event resolved | admin+ |
| POST | /api/v1/abuse/mailboxes/{mailboxID}/suspend | Suspend a mailbox for abuse | admin+ |
| POST | /api/v1/abuse/mailboxes/{mailboxID}/unsuspend | Restore a suspended mailbox | admin+ |

---

## A.11 Per-domain analytics (Pro feature)

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/analytics | Per-domain analytics dashboard data | session, gated by `analytics` |

Behaviour at the gate:
- ValidonX unconfigured → pass-through (Free-everywhere mode for self-hosters)
- Active Pro license → 200
- Lapsed past 30-day grace → 403 `LICENSE_EXPIRED`
- Free tier with ValidonX configured → 403 `FEATURE_NOT_AVAILABLE`

---

## A.12 License management

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/license | Current license status (tier / expiry / features) | super |
| POST | /api/v1/license | Activate / re-validate license against ValidonX | super |
| DELETE | /api/v1/license | Clear license (drops to Free) | super |

- POST runs a ValidonX probe; on success persists to `validonx_config` and atomically swaps the running gate client (no api restart).
- Beta1 (current) calls path-1 (`/api/v1/integration/entitlements/check`); v0.1.0 stable swaps to path-2 (`/v1/integration/licensing/resolve`). See [`docs/notes/deferred-items.md` §11](../notes/deferred-items.md).

---

## A.12a Customer account / billing portal

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| POST | /api/v1/account/billing-portal-session | Mint a Stripe Customer Portal session via ValidonX and return the redirect URL | super |

- Backs the admin-UI `/account/billing` page so the customer never sees the ValidonX brand.
- Unlike Pro-feature gates, this route does NOT require an active license — past_due / cancelled customers must be able to reach the portal to reactivate.
- Marketing-site counterpart at `vectismail.com/account/billing` proxies the same flow for welcome-email CTAs.

---

## A.12b Custom branding (Pro feature)

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/branding | Get current branding config (logo URL, accent colour, login footer) | super |
| PUT | /api/v1/branding | Set / update branding config | super, gated by `custom_branding` |
| DELETE | /api/v1/branding | Clear branding overrides (revert to defaults) | super, gated by `custom_branding` |

- GET is ungated so Free installs can still fetch defaults on every page load.
- PUT and DELETE require the `custom_branding` Pro feature; Free installs return 403 `FEATURE_NOT_AVAILABLE`.

---

## A.13 Deliverability (advanced)

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/deliverability/warmup | List active IP-warmup schedules | super |
| POST | /api/v1/deliverability/warmup | Create warmup schedule | super |
| DELETE | /api/v1/deliverability/warmup/{warmupID} | Cancel warmup schedule | super |
| GET | /api/v1/deliverability/rbl | Current RBL status (cached) | super |
| POST | /api/v1/deliverability/rbl/check | Trigger fresh RBL check | super |
| GET | /api/v1/deliverability/fbl | List feedback-loop reports | super |
| POST | /api/v1/deliverability/fbl | Configure new FBL provider | super |

---

## A.14 Configuration

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/config | Get current config (secrets redacted) | super |
| GET | /api/v1/config/diff | Diff between current and desired state | super |
| POST | /api/v1/config/validate | Validate config without applying | super |
| POST | /api/v1/config/apply | Apply config changes (triggers reload/restart per matrix) | super |

---

## A.15 Orchestrator (Updates page)

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| POST | /api/v1/orchestrator/plan | Generate update plan (read-only) | super |
| POST | /api/v1/orchestrator/apply | Execute the stored plan | super |
| POST | /api/v1/orchestrator/rollback | Roll back last update | super |
| GET | /api/v1/orchestrator/status | Current orchestrator state machine state | super |
| GET | /api/v1/orchestrator/history | Past Apply / Rollback operations | super |

### Concurrency behaviour

If the orchestrator is busy (state ≠ idle), all mutating endpoints return `409 Conflict`:

```json
{
  "error": {
    "code": "ORCHESTRATOR_BUSY",
    "message": "Orchestrator is currently applying updates",
    "details": {
      "current_state": "applying",
      "started_at": "2026-04-27T12:00:00Z"
    }
  }
}
```

State transitions are documented in [Spec D — Orchestrator State Machine](D_Orchestrator_State_Machine.md).

---

## A.16 System (per-service health, logs, metrics)

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/health/{service} | Detailed health for one service | super |
| GET | /api/v1/logs/{service} | Service logs (tail / since / until / follow) | super |
| GET | /api/v1/logs/search | Cross-service log search | super |
| GET | /api/v1/metrics | System metrics snapshot (CPU / mem / disk / mail queue) | super |

---

## A.17 Alerts

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/alerts | List recent alerts | super |
| POST | /api/v1/alerts/check | Run a one-shot health check now | super |

---

## A.18 Backup / Restore

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| POST | /api/v1/backup/create | Trigger full backup (returns job ID) | super |
| POST | /api/v1/backup/incremental | Trigger incremental backup | super |
| GET | /api/v1/backup/status/{jobId} | Check backup-job progress | super |
| GET | /api/v1/backup/list | List available backups | super |
| POST | /api/v1/backup/restore/{id} | Trigger restore (`X-Confirm-Restore: true`) | super |

### Backup as async job

Backup creation returns immediately with a job ID:

```json
{ "data": { "job_id": "uuid", "status": "pending" } }
```

Client polls `GET /backup/status/{jobId}` for progress.

---

## A.19 Cluster (HA / rolling updates)

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /api/v1/cluster/status | Cluster health summary | super |
| GET | /api/v1/cluster/nodes | List cluster nodes | super |
| DELETE | /api/v1/cluster/nodes/{nodeID} | Remove node from cluster | super |
| POST | /api/v1/cluster/rolling-update | Start rolling update across cluster | super |
| POST | /api/v1/cluster/rolling-rollback | Roll back rolling update | super |
| GET | /api/v1/cluster/operations | List rolling-operation history | super |
| GET | /api/v1/cluster/operations/{operationID} | Get one rolling-operation detail | super |

Cluster endpoints are present at v0.1.0 but full multi-node behaviour ships with the Enterprise tier (Phase 4).

---

## A.20 Static assets / SPA

The admin UI bundle is served from the same Go binary:

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| GET | /assets/* | SPA assets (JS / CSS / images) | none |
| GET | /* (non-API) | SPA fallback to `index.html` | none |

Non-`/api/`, non-`/assets/` routes that don't match a file fall back to `index.html` (SPA routing). API 404s return JSON: `{"error":{"code":"NOT_FOUND","message":"Endpoint not found"}}`.

---

## A.21 API Design Conventions

- **Pagination:** Cursor-based using `?cursor=xxx&limit=50` (default limit 50, max 200)
- **Filtering:** Query parameters per resource (e.g., `?domain_id=xxx&active=true`)
- **Sorting:** `?sort=created_at&order=desc`
- **Long-running operations:** Return job ID immediately; client polls for status
- **Audit trail:** All mutating endpoints log an entry in the `audit_log` table
- **API versioning:** URL prefix (`/api/v1`); breaking changes require a new version
- **Content type:** `application/json` for all requests and responses
- **Rate limiting:** Traefik middleware, configurable per endpoint group
- **CORS:** Disabled by default; configurable for custom UI integrations
- **Content negotiation:** Pro feature gates on browser-facing routes (e.g. OIDC) honour the `Accept` header — `text/html` (or `*/*`/missing) returns a 402 + HTML upgrade page; explicit `application/json` returns the 403 JSON envelope.

---

## Refresh procedure

When a route is added/removed/renamed:

```bash
# Canonical route list — handles single-line `.Get("/path", ...)` AND
# split-line `r.With(...).\n    Get("/path", ...)` cases.
grep -oE '(Get|Post|Put|Patch|Delete)\("/[^"]+"' internal/api/server.go \
  | awk -F'"' '{print $2}' | sort -u
```

Compare against the tables above and reconcile. Bump the "Last refreshed" date + commit hash at the top.
