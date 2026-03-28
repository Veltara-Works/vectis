# A. API Endpoint Inventory

**Status:** DRAFT — For review with Copilot before integration into Spec v1.1  
**Prepared by:** Claude (round 5)  
**Complements:** Vectis Architecture v1.3, Implementation Spec v1.0

---

## A.1 Overview

All endpoints are prefixed with `/api/v1`. Authentication is required for all endpoints except `/api/v1/health` and `/api/v1/auth/login`.

All responses use a consistent JSON envelope:

```json
{
  "data": { ... },
  "error": null,
  "meta": {
    "request_id": "uuid",
    "timestamp": "2026-03-28T12:00:00Z"
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

---

## A.2 Authentication

| Method | Endpoint | Purpose | Auth |
|--------|----------|---------|------|
| POST | /api/v1/auth/login | Authenticate admin, return session cookie | None |
| POST | /api/v1/auth/logout | Invalidate current session | Required |
| POST | /api/v1/auth/logout-all | Invalidate all sessions for current admin | Required |
| GET | /api/v1/auth/sessions | List active sessions for current admin | Required |
| DELETE | /api/v1/auth/sessions/:id | Invalidate a specific session | Required |
| POST | /api/v1/auth/totp/setup | Begin TOTP enrolment (returns QR URI) | Required |
| POST | /api/v1/auth/totp/verify | Confirm TOTP enrolment with first code | Required |
| DELETE | /api/v1/auth/totp | Remove TOTP (requires current TOTP code) | Required |

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

## A.3 Domains

| Method | Endpoint | Purpose | Notes |
|--------|----------|---------|-------|
| GET | /api/v1/domains | List all domains | Paginated, filterable by active status |
| POST | /api/v1/domains | Create domain | Triggers DKIM key generation |
| GET | /api/v1/domains/:id | Get domain details | Includes DKIM status, mailbox count |
| PATCH | /api/v1/domains/:id | Update domain settings | Spam threshold, max mailboxes, active |
| DELETE | /api/v1/domains/:id | Remove domain | Fails if mailboxes exist (409 Conflict) |
| POST | /api/v1/domains/:id/dkim/generate | Generate new DKIM key pair | Stores key, returns DNS TXT record |
| GET | /api/v1/domains/:id/dkim | Get DKIM public key as DNS TXT record | For admin to copy into DNS provider |
| POST | /api/v1/domains/:id/dkim/rotate | Rotate DKIM key with new selector | Keeps old key active during transition window |
| GET | /api/v1/domains/:id/deliverability | Run deliverability checks | SPF, DKIM, DMARC, PTR, TLS status |

### Domain creation flow

1. `POST /domains` with `{ name: "example.com" }`
2. API validates domain name format
3. API inserts domain into Postgres
4. API generates DKIM key pair (RSA-2048, see Section C for DKIM details)
5. API stores private key in `/var/vectis/dkim/<domain>/`
6. API triggers Rspamd config reload (for DKIM signing config)
7. API returns domain object + DKIM DNS record to display
8. Postfix and Dovecot pick up the new domain via live SQL lookup — no reload needed

### Domain deletion constraints

- Cannot delete a domain that has mailboxes (return 409 with count of existing mailboxes)
- Cannot delete a domain that has aliases (return 409 with count of existing aliases)
- Admin must explicitly delete all mailboxes and aliases first
- This prevents accidental data loss

---

## A.4 Mailboxes

| Method | Endpoint | Purpose | Notes |
|--------|----------|---------|-------|
| GET | /api/v1/mailboxes | List mailboxes | Filterable by domain_id, active status |
| POST | /api/v1/mailboxes | Create mailbox | Password hashed with Argon2id |
| GET | /api/v1/mailboxes/:id | Get mailbox details | Includes quota usage |
| PATCH | /api/v1/mailboxes/:id | Update mailbox | Quota, active, password, display name |
| DELETE | /api/v1/mailboxes/:id | Delete mailbox | Requires confirmation header |

### Mailbox creation flow

1. `POST /mailboxes` with `{ domain_id, local_part, password, quota_mb?, display_name? }`
2. API validates domain exists and is active
3. API validates local_part uniqueness within domain
4. API hashes password with Argon2id
5. API inserts mailbox into Postgres
6. API creates Maildir structure on disk: `/var/vectis/mail/<domain>/<local_part>/Maildir/{cur,new,tmp}`
7. Postfix and Dovecot pick up the new mailbox via live SQL lookup — no reload needed

### Mailbox deletion

- Requires `X-Confirm-Delete: true` header
- Optionally archives mail data before deletion (controlled by request body `{ archive: true }`)
- If archiving: copies Maildir to `/var/vectis/archives/<domain>/<local_part>-<timestamp>/`
- Removes mailbox from Postgres
- Removes Maildir from disk (unless archived)

---

## A.5 Aliases

| Method | Endpoint | Purpose | Notes |
|--------|----------|---------|-------|
| GET | /api/v1/aliases | List aliases | Filterable by domain_id |
| POST | /api/v1/aliases | Create alias | Source and destination(s) |
| GET | /api/v1/aliases/:id | Get alias details | |
| PATCH | /api/v1/aliases/:id | Update alias | Change destination(s), active status |
| DELETE | /api/v1/aliases/:id | Delete alias | |

### Alias notes

- `source_local_part` can be empty string for catch-all aliases
- `destination` can be a single address or comma-separated list
- Aliases take effect immediately via Postfix SQL lookup — no reload needed

---

## A.6 Orchestrator Control

| Method | Endpoint | Purpose | Notes |
|--------|----------|---------|-------|
| POST | /api/v1/orchestrator/plan | Generate update plan | Returns plan diff; read-only operation |
| POST | /api/v1/orchestrator/apply | Execute the stored plan | Requires prior plan; takes DB snapshot first |
| POST | /api/v1/orchestrator/rollback | Rollback last update | Restores DB snapshot + previous container versions |
| GET | /api/v1/orchestrator/status | Current orchestrator state | Returns state machine state (see Section D) |
| GET | /api/v1/orchestrator/history | Update history | Paginated list of past operations |

### Concurrency behaviour

- If the orchestrator is busy (state != idle), all mutating endpoints return `409 Conflict` with:

```json
{
  "error": {
    "code": "ORCHESTRATOR_BUSY",
    "message": "Orchestrator is currently applying updates",
    "details": {
      "current_state": "applying",
      "started_at": "2026-03-28T12:00:00Z"
    }
  }
}
```

---

## A.7 Configuration

| Method | Endpoint | Purpose | Notes |
|--------|----------|---------|-------|
| GET | /api/v1/config | Get current config (redacted) | Secrets replaced with `***` placeholders |
| GET | /api/v1/config/diff | Show pending config changes | Diff between current and desired state |
| POST | /api/v1/config/apply | Apply config changes | Triggers reload/restart per matrix |
| POST | /api/v1/config/validate | Validate config without applying | Returns validation errors if any |

---

## A.8 System

| Method | Endpoint | Purpose | Notes |
|--------|----------|---------|-------|
| GET | /api/v1/health | System health summary | No auth required; per-service up/down |
| GET | /api/v1/health/:service | Individual service health | Detailed health for one service |
| GET | /api/v1/logs/:service | Service logs | Query params: tail, since, until, follow |
| GET | /api/v1/metrics | System metrics snapshot | CPU, memory, disk, mail queue length |
| GET | /api/v1/version | Vectis version info | API version, per-container image versions |

---

## A.9 Backup

| Method | Endpoint | Purpose | Notes |
|--------|----------|---------|-------|
| POST | /api/v1/backup/create | Trigger backup | Returns job ID for polling |
| GET | /api/v1/backup/status/:jobId | Check backup progress | Progress percentage, current step, errors |
| GET | /api/v1/backup/list | List available backups | Timestamps, sizes, completeness |
| POST | /api/v1/backup/restore/:id | Trigger restore | Requires `X-Confirm-Restore: true` header |

### Backup as async job

Backup creation is a long-running operation. The API returns immediately with a job ID:

```json
{
  "data": {
    "job_id": "uuid",
    "status": "pending"
  }
}
```

Client polls `GET /backup/status/:jobId` for progress updates.

---

## A.10 API Design Conventions

- **Pagination:** Cursor-based using `?cursor=xxx&limit=50` (default limit 50, max 200)
- **Filtering:** Query parameters per resource (e.g., `?domain_id=xxx&active=true`)
- **Sorting:** `?sort=created_at&order=desc`
- **Long-running operations:** Return job ID immediately; client polls for status
- **Audit trail:** All mutating endpoints log an entry in the `audit_log` table
- **API versioning:** URL prefix (`/api/v1`); breaking changes require a new version
- **Content type:** `application/json` for all requests and responses
- **Rate limiting:** Traefik middleware, configurable per endpoint group
- **CORS:** Disabled by default; configurable for custom UI integrations
