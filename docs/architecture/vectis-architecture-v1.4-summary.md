# Vectis Architecture v1.4 (FINAL — Ratified)

**Status:** RATIFIED — No further architecture iterations required  
**Reviewed:** 6 rounds of critique by Claude (Opus 4.6)  
**Date:** March 2026

---

## 1. Product Identity

- **Product name:** Vectis
- **Descriptor:** "Vectis Mail"
- **Ecosystem:** Veltara Works
- **Licensing:** ValidonX (Pro/Enterprise features)
- **Positioning:** "Self-hosted email that scales from one server to a cluster, with updates you can trust and config you can read."

---

## 2. Source-of-Truth Model

| Store | Contains | Rule |
|-------|----------|------|
| config.yaml | Infrastructure policy: TLS, resource profiles, ClamAV/Rspamd profiles, orchestrator timeouts, backup profiles, alerting, registry settings | "What the system is" |
| Postgres | Operational entities: domains, mailboxes, aliases, admins, sessions, orchestrator history, audit log | "What the system contains" |
| secrets.yaml | Sensitive values: DB passwords, Valkey password, API secret, orchestrator token, registry credentials, DKIM key paths | "What must never hit git" |

**Domains live in Postgres** (not config.yaml). This simplifies the config engine, enables live SQL lookups, and eliminates file-locking for day-to-day admin operations.

---

## 3. Containerised Services (Phase 1)

| Service | Purpose |
|---------|---------|
| Postfix | SMTP (25, 465, 587) |
| Dovecot | IMAP/POP3 (993, 995) |
| Rspamd | Spam filtering, DKIM signing, DMARC/SPF/ARC |
| ClamAV | Antivirus (profile-based: none/dev/small/production/enterprise) |
| Valkey | Redis-compatible cache (DB 0) + async queue (DB 1, persistent) |
| Postgres | Primary relational database |
| Go API | Backend API + config engine + CLI |
| React Admin UI | Web admin interface |
| Update Orchestrator | Atomic updates, rollback, versioning |
| ValidonX Agent | Optional licensing container |
| Traefik | Reverse proxy + automatic SSL for HTTP |
| cert-extractor sidecar | Splits Traefik's `acme.json` into PEM and HUPs mail services on cert rotation (replaces former acme.sh sidecar; see ADR-009) |

---

## 4. Host OS (Minimal)

- Ubuntu 24.04 LTS
- Docker Engine + Docker Compose
- Fail2ban (host-level, for SSH + SMTP brute force)
- Unattended security upgrades
- Basic utilities
- **Nothing else** — no Nginx, no PHP, no MariaDB, no Redis, no mail services

---

## 5. Key Architectural Decisions

1. **Traefik** (containerised) replaces Nginx + Certbot
2. **Postgres only** — no MariaDB option
3. **Rspamd** handles DKIM/DMARC/SPF/ARC — no OpenDKIM/OpenDMARC
4. **Valkey** over Redis (licensing clarity)
5. **Go + Chi** for API, **React + TypeScript** for Admin UI
6. **Maildir** format at `/var/vectis/mail/` with bind mounts
7. **Direct SQL lookups** — Postfix/Dovecot query Postgres for domains/mailboxes/aliases (live, no reload needed)
8. **TCP LMTP** between Postfix and Dovecot (port 24, over Docker network)
9. **Forward-only migrations** with snapshot-based rollback (golang-migrate, embedded)
10. **Orchestrator** is the only container with Docker socket access
11. **Four container networks:** frontend, mail, data, orchestrator
12. **Three Postgres users:** vectis_postfix (read-only), vectis_dovecot (read-only), vectis_api (full)
13. **cert-extractor sidecar** reuses Traefik's ACME certs for SMTP/IMAP — single ACME flow, no separate sidecar (see ADR-009)
14. **GHCR** for container images (public-read Free, private Pro)

---

## 6. Reload/Restart Matrix

### SQL-driven (no action required)
- Add/remove mailbox, alias, domain
- Change mailbox password, quota
- Enable/disable mailbox or domain

### Reload
- DKIM key change → Rspamd reload
- Per-domain spam threshold → Rspamd reload
- TLS settings → Postfix + Dovecot reload

### Restart / Full Apply
- ClamAV profile change → restart or full apply
- Resource limit change → full apply
- Container image update → full apply

---

## 7. Orchestrator State Machine

States: idle → planning → validating → applying → rolling_back → failed → completed

- Postgres advisory lock for concurrency
- DB snapshot (pg_dump) before every apply
- Rollback = restore snapshot + revert containers
- Self-update handled by CLI on host (bypasses orchestrator)

---

## 8. Security

- Admin auth: Argon2id + signed cookies + Valkey sessions + Traefik rate limiting
- TOTP MFA in Phase 1.5
- secrets.yaml: mode 0600, owned by vectis user
- Orchestrator: internal HTTP with bearer token (mTLS in Phase 2)
- Container isolation via named Docker networks

---

## 9. Phasing

| Phase | Scope |
|-------|-------|
| 0.5 | Mail stack, config engine, minimal UI, DKIM, logging |
| 1 | Full UI, orchestrator, licensing, deliverability, backup, monitoring |
| 2 | Webmail, OIDC, mTLS, advanced deliverability |
| 3 | Clustering, PgBouncer, multi-node orchestrator |
| 4 | SAML, Azure AD, multi-tenant, compliance |

---

## 10. Deployment

- **Dev:** Sydney VPS, `mail-dev.vectismail.com`
- **Production:** Clone to Singapore VPS post-testing
- **Install:** Two-step (preflight + install)
- **Git:** `github.com/Veltara-Works/vectis` (private)
