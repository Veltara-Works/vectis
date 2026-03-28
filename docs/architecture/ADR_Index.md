# Vectis — Architectural Decision Record (ADR) Index

**Status:** All decisions RATIFIED  
**Date:** March 2026  
**Source:** 6 rounds of architectural review (Claude + Copilot)

---

These 25 decisions were made across six review rounds. They are binding for implementation unless explicitly revisited.

---

## Infrastructure Decisions

### ADR-001: Traefik replaces Nginx + Certbot
- **Context:** Host-level Nginx creates split-brain config (some config in containers, some on host)
- **Decision:** Traefik runs as a container, auto-manages HTTP/HTTPS certs via ACME
- **Consequence:** No Nginx on host; Traefik labels in Docker Compose drive routing

### ADR-002: Postgres only (no MariaDB option)
- **Context:** Supporting both doubles testing surface and schema management
- **Decision:** Postgres for Phase 1 and all foreseeable phases
- **Consequence:** Better JSON support, better clustering story, simpler engineering

### ADR-003: Valkey over Redis
- **Context:** Redis licensing changes (SSPL) create uncertainty
- **Decision:** Valkey (Linux Foundation, BSD-licensed, Redis-compatible)
- **Consequence:** Drop-in replacement; use existing Redis client libraries

### ADR-004: Maildir format with bind mounts
- **Context:** Mail storage format affects backup, restore, and debugging
- **Decision:** Maildir at `/var/vectis/mail/<domain>/<local_part>/Maildir/`
- **Consequence:** Easy backup (rsync), easy restore, easy inspection; each message is a file

### ADR-005: GHCR for container registry
- **Context:** Need a registry for Vectis container images
- **Decision:** GitHub Container Registry; public-read for Free tier, private for Pro
- **Consequence:** Free, global CDN, integrates with GitHub CI/CD

---

## Mail Stack Decisions

### ADR-006: Rspamd replaces OpenDKIM + OpenDMARC
- **Context:** Rspamd handles DKIM signing and DMARC verification natively
- **Decision:** Remove OpenDKIM and OpenDMARC containers; Rspamd does everything
- **Consequence:** Fewer containers, simpler operations, consistent with Mailcow's approach

### ADR-007: ClamAV profiles including "none"
- **Context:** ClamAV uses 1-2 GB RAM; too heavy for small deployments
- **Decision:** Profile system: none (omit container), dev, small, production, enterprise
- **Consequence:** Small deployments skip ClamAV entirely; config engine omits it from Compose

### ADR-008: TCP LMTP between Postfix and Dovecot
- **Context:** Postfix delivers to Dovecot; Unix socket requires shared volume in containers
- **Decision:** Dovecot listens on TCP port 24 (inet_listener); Postfix uses `lmtp:inet:dovecot:24`
- **Consequence:** Works cleanly over Docker networking; no shared socket volume needed

### ADR-009: acme.sh sidecar for mail TLS certificates
- **Context:** Traefik manages HTTP certs but Postfix/Dovecot need their own TLS certs for SMTP/IMAP
- **Decision:** Separate acme.sh container provisions certs for mail hostname, writes to shared volume
- **Consequence:** Mail certs managed independently of HTTP certs; both auto-renew

### ADR-010: Direct SQL lookups for Postfix/Dovecot
- **Context:** Postfix/Dovecot need to know about domains, mailboxes, aliases
- **Decision:** Postfix uses `pgsql:` map type; Dovecot uses SQL passdb/userdb; both query Postgres directly
- **Consequence:** Adding a mailbox takes effect immediately — no config reload needed

---

## Source-of-Truth Decisions

### ADR-011: Hybrid source-of-truth model
- **Context:** Need to decide what goes in config files vs database
- **Decision:** config.yaml = policy ("what the system is"), Postgres = entities ("what the system contains"), secrets.yaml = sensitive values
- **Consequence:** Clear boundary rules for where new settings go as product evolves

### ADR-012: Domains live in Postgres
- **Context:** Domains are operational entities created through normal admin operations
- **Decision:** Store domains in Postgres, not config.yaml
- **Consequence:** Simplifies config engine (no file writes for common operations); Postfix queries domains via SQL

---

## API & Code Decisions

### ADR-013: Go + Chi for backend API
- **Context:** Need a language/framework for the API and CLI
- **Decision:** Go with Chi router
- **Consequence:** Low memory, fast, good concurrency, single binary, idiomatic middleware

### ADR-014: React + TypeScript for Admin UI
- **Context:** Need a frontend framework for the admin panel
- **Decision:** React + TypeScript
- **Consequence:** Modern, maintainable, large ecosystem, good developer pool

### ADR-015: golang-migrate with embedded migrations
- **Context:** Need a migration tool; must integrate with orchestrator rollback
- **Decision:** golang-migrate; migration files embedded in Go binary via `embed` package
- **Consequence:** Each version carries its own migrations; orchestrator can inspect pending migrations

### ADR-016: Forward-only migrations with snapshot rollback
- **Context:** Reverse migrations are fragile and can cause data loss
- **Decision:** No reverse migrations; rollback = restore from pg_dump snapshot
- **Consequence:** Simpler, more reliable; must take snapshot before every apply

---

## Security Decisions

### ADR-017: Orchestrator-only Docker socket access
- **Context:** Docker socket access = root on host; minimize exposure
- **Decision:** Only the orchestrator container mounts the Docker socket; API communicates via authenticated internal HTTP
- **Consequence:** Compromised API container cannot control other containers directly

### ADR-018: Four named container networks
- **Context:** Need network isolation between service groups
- **Decision:** vectis-frontend, vectis-mail, vectis-data, vectis-orchestrator
- **Consequence:** Principle of least privilege; Admin UI cannot reach Postgres; orchestrator cannot read mail

### ADR-019: Three Postgres users with different privileges
- **Context:** Defence in depth for database access
- **Decision:** vectis_postfix (read-only), vectis_dovecot (read-only), vectis_api (full access)
- **Consequence:** Compromised Postfix/Dovecot cannot modify data

### ADR-020: Admin auth stack
- **Context:** Admin panel controls email infrastructure; must be secure
- **Decision:** Argon2id password hashing + signed cookies + Valkey sessions + Traefik rate limiting + TOTP MFA (Phase 1.5)
- **Consequence:** Modern, layered security; session invalidation supported

---

## Operational Decisions

### ADR-021: Two-step install (preflight + install)
- **Context:** One-command install is fragile and creates support burden
- **Decision:** `vectis preflight` (validate environment) then `vectis install` (deploy)
- **Consequence:** Better UX; clear error messages before any changes are made

### ADR-022: Bootstrap lifecycle
- **Context:** Config engine runs inside a container but generates the Compose file that defines containers
- **Decision:** Installer uses a minimal template Compose; once API boots, config engine generates the full Compose; orchestrator applies it
- **Consequence:** Clean handoff from installer to config engine; no chicken-and-egg

### ADR-023: Rspamd DKIM config generated from Postgres
- **Context:** Domains are in Postgres but Rspamd needs config files for DKIM signing
- **Decision:** Config engine queries Postgres for domain list, generates dkim_signing.conf, triggers Rspamd reload
- **Consequence:** Adding a domain requires Rspamd reload (not just a DB operation); acknowledged exception to the "SQL-driven = no reload" pattern

### ADR-024: Structured JSON logging for Go services, native formats for mail services
- **Context:** Multiple services with different log formats
- **Decision:** Go API + orchestrator use structured JSON (slog/zerolog); Postfix/Dovecot/Rspamd/ClamAV keep native formats
- **Consequence:** Admin UI log viewer must handle multiple formats; but troubleshooting guides can reference standard service documentation

### ADR-025: Dev in Sydney, production clone to Singapore
- **Context:** Developer is in Australia; low-latency dev sessions matter
- **Decision:** Build and test on Sydney VPS; clone to Singapore for production
- **Consequence:** PTR/DNS records will change on clone; deliverability tools will guide this
