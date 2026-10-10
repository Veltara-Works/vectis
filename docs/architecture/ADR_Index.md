# Vectis — Architectural Decision Record (ADR) Index

**Status:** All decisions RATIFIED  
**Date:** March 2026  
**Source:** 6 rounds of architectural review (Claude + Copilot)

---

These 25 decisions were made across six review rounds; ADR-026 was added on 2026-10-10. All are binding for implementation unless explicitly revisited.

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

### ADR-009: Mail TLS certificate provisioning
- **Context:** Traefik manages HTTP certs but Postfix/Dovecot need their own TLS certs for SMTP/IMAP
- **Decision (original, superseded):** Separate `acme.sh` sidecar container would provision certs for the mail hostname and write to a shared volume.
- **Decision (current):** Reuse the cert already issued by Traefik. A `cert-extractor` sidecar parses `acme.json` (Traefik's ACME state), splits the cert + key into PEM files on a shared volume, and signals Postfix + Dovecot via `docker kill --signal=HUP` whenever the cert rotates. The `acme.sh` sidecar is removed entirely.
- **Consequence:** Single ACME flow (Traefik), single source of cert truth. No risk of HTTP and mail certs drifting. Cert-extractor's Docker-socket access is scoped via ADR-017. Implementation: `internal/engine/templates/docker-compose.yml.tmpl` lines 419-460, `internal/tls/traefik_extract.go`.
- **History:** Original decision shipped with the v0.0.x architecture; cert-extractor superseded acme.sh before v0.1.0 stable (commit history at `internal/tls/traefik_extract.go`). 2026-05-17 audit (P6-M2) flagged that ADR-009 still documented the removed acme.sh path.

### ADR-010: Direct SQL lookups for Postfix/Dovecot
- **Context:** Postfix/Dovecot need to know about domains, mailboxes, aliases
- **Decision:** Postfix uses `pgsql:` map type; Dovecot uses SQL passdb/userdb; both query Postgres directly
- **Consequence:** Adding a mailbox takes effect immediately — no config reload needed

### ADR-026: Rspamd resolves through a bundled local recursive resolver
- **Context:** Rspamd's DNSBL/URIBL/DNSWL lookups inherit the host resolver (Docker `127.0.0.11` → `systemd-resolved` → the VPS provider's shared resolver and/or `8.8.8.8`). Those blocklists refuse queries from shared and public resolvers. On both production boxes (2026-10-10, #258), URIBL refuses every query, and Spamhaus ZEN and DNSWL fail intermittently. Spam scoring silently loses its blocklist component on every default install, while rspamd stays healthy.
- **Decision:** Ship `unbound` **inside the `vectis-rspamd` image** as a local, recursion-only resolver bound to `127.0.0.1:53`. The entrypoint runs it in a restart loop (a background shell that relaunches unbound whenever it exits and reaps it itself; it stays a child of rspamd after the entrypoint `exec`s rspamd as PID 1), and only starts rspamd once unbound answers. Rspamd uses it via a baked `override.d/options.inc`: `dns { nameserver = ["127.0.0.1:53"]; }`. Unbound sends queries from the box's own IP over `vectis-mail`, which already has internet access, so blocklists see the install's own address instead of a shared or public resolver. Whether that use is free is set by each provider's terms and the operator's own use, not by Vectis. Opt-out: `rspamd.local_resolver: false` renders `VECTIS_RSPAMD_LOCAL_RESOLVER=false`; the entrypoint then skips unbound and **deletes the baked `options.inc`**, so rspamd falls back to the container's default resolver, and the healthcheck drops its resolver probe. Being a container-level setting, it takes effect when rspamd is recreated.
- **Consequence:** No new container, no new network, no new bind mount; the four-network model (ADR network invariant) and ADR-017's socket rules are unchanged. The rspamd image gains ~1 MB and a second supervised process. A resolver failure is a scoring failure, so the healthcheck covers both: rspamd's `/ping` plus a query for a static local record (no upstream lookup, so an internet blip doesn't fail it). The DNS cache resets whenever rspamd restarts (acceptable at our volume). Operators whose use or volume falls outside a blocklist provider's free terms need that provider's paid access; for Spamhaus, an operator-supplied DQS key is the follow-up (#260).
- **Alternatives considered:**
  1. **Separate `unbound` container with `network_mode: service:rspamd`:** cleaner one-process-per-container, but adds a ninth image to sign, verify and pin, and couples its lifecycle to rspamd's network namespace in ways the orchestrator's recreate logic doesn't handle today.
  2. **Separate `unbound` container on `vectis-mail` with a static IP:** needs fixed IPAM subnets on `vectis-mail`, which existing installs don't have. Changing a live network's subnet means recreating it, a risky migration.
  3. **Host-level `unbound` installed by the installer:** moves mail-path state onto the host, outside the container and update model; not covered by `vectis verify` or the update pipeline.
  4. **Spamhaus DQS key only:** fixes Spamhaus, not URIBL or DNSWL. Complementary, not a substitute.
- **Status:** Ratified 2026-10-10 (Ian). Tracking issue #258; implementation targets v0.1.53. Operator-supplied Spamhaus DQS key is a separate opt-in follow-up (#260).

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

### ADR-017: Minimal Docker socket exposure
- **Context:** Docker socket access = root on host; minimize exposure
- **Decision:** Three containers mount the Docker socket, each with the minimum capability needed for a specific operational requirement:
  - **`vectis-orchestrator`** — `:ro` mount; manages full compose stack lifecycle (Plan/Apply, image pulls, container recreate). Primary socket-holder.
  - **`vectis-promtail`** — `:ro` mount; required for `docker_sd_configs` log-label discovery so per-container labels appear in Loki.
  - **`vectis-cert-extractor`** — RW mount; required for `docker kill --signal=HUP` on mail-stack containers when Traefik writes new certs.

  No other container has socket access; API talks to the orchestrator over authenticated internal HTTP for any container-control operation.
- **Consequence:** Compromised API container cannot control other containers directly. Compromised promtail or cert-extractor has tightly-scoped blast radius (read-only socket plus, for cert-extractor, the ability to send HUP signals to known mail containers). Original "orchestrator-only" rule from 2026-03 was relaxed to accept these two minimal-blast-radius helpers; revisit if a cAdvisor-style or file-watch alternative removes the need for socket access.
- **History:** Drift first acknowledged in 2026-05-17 audit (P6-M1) — code was at 3 sockets, ADR still said 1. Updated to reflect reality.

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

