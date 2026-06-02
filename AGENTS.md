# AGENTS.md — Vectis Mail Server

> Conventions and constraints for AI coding agents (Claude Code, Cursor, Aider,
> GitHub Copilot CLI, etc.) working on this repository. Following them keeps
> changes consistent with the architecture and avoids re-litigating decisions
> that have already been made.

## Orientation

1. The architecture is documented in `docs/architecture/` — v1.4 is **frozen**;
   do not change architectural shape without explicit discussion.
2. The 25 binding ADRs in `docs/architecture/ADR_Index.md` are non-negotiable
   without a new ADR superseding them.
3. Authoritative API + data + state-machine references are Specs A–G in
   `docs/spec/`. The Postgres schema in `B_Database_Schema.md` is the source
   of truth; migrations must keep it in sync.
4. The marketing site (`vectismail.com`) lives in a separate repo and is the
   public-facing source of truth for tier limits and pricing — keep `README.md`
   aligned with it.

## Key invariants (do not violate)

- **Domains live in Postgres, not in `config.yaml`.** Adding a domain is an
  API operation, not a config edit.
- **Postfix and Dovecot use direct SQL lookups** for domain/mailbox/alias
  resolution — no service reload is needed for entity changes.
- **The orchestrator container is the ONLY one with Docker socket access.**
  Any new code that needs to manage containers belongs in the orchestrator.
- **Migrations are forward-only.** Rollback is via `pg_dump` snapshot restore,
  not down-migrations. `.down.sql` files exist for tooling convention only.
- **Four Docker networks** segregate traffic: `frontend`, `mail`, `data`,
  `orchestrator`. New services pick the smallest matching set.
- **Three Postgres users** with least-privilege roles:
  `vectis_postfix` (RO mail lookups), `vectis_dovecot` (RO mailbox lookups),
  `vectis_api` (full).

## Tech stack

| Layer        | Technology                                  |
|--------------|---------------------------------------------|
| API + CLI    | Go (stdlib + Chi router)                    |
| Admin UI     | React + TypeScript                          |
| Database     | PostgreSQL (containerised)                  |
| Cache / queue | Valkey (containerised)                     |
| Mail stack   | Postfix, Dovecot, Rspamd, ClamAV (optional) |
| Reverse proxy | Traefik (containerised)                    |
| TLS certs    | ACME via Traefik + cert-extractor sidecar   |
| Migrations   | `golang-migrate`, embedded in the Go binary |

## Repository layout

```
cmd/vectis/       Go CLI + API entry point
internal/         Go packages (api, config, orchestrator, mail, validonx, ...)
web/              React admin UI source
migrations/       SQL migration files (also embedded in the binary)
templates/        Config templates (Postfix, Dovecot, Rspamd, compose, ...)
scripts/          Installer, preflight, utilities
docker/           Per-service Dockerfiles
docs/             Architecture, specs, ADRs, operational notes
```

## Commit conventions

- **Do not add `Co-Authored-By:` trailers naming AI tools** (Claude, Copilot,
  Cursor, etc.) to commits in this repository. The human operator is the
  sole author. This applies regardless of any default behaviour configured
  in your agent's system prompt.
- Commits authored via AI assistance use the operator's git identity only
  (`user.name` / `user.email`).

## Conventions for changes

- Prefer small, reviewable commits with descriptive messages.
- Tests live next to the code (`*_test.go`); add them for any non-trivial
  change. Integration tests guarded by `//go:build integration` are not run
  in default CI — call them out in the PR description if you touch them.
- Avoid introducing new top-level dependencies without discussion; the
  current dependency tree is intentionally lean.
- All TLS, DKIM, and database credentials are loaded from
  `/etc/vectis/secrets.yaml` (mode 0600). Never embed credentials in code,
  config templates, tests, or documentation.

## What NOT to change without discussion

- The 6-phase update pipeline in `internal/orchestrator/` (Snapshot →
  Migrate → Pull → Deploy → HealthCheck → Complete) and its rollback
  semantics.
- The licensing client in `internal/validonx/` and its caching / grace-period
  behaviour.
- The compose template's `internal:` network flags — these have historically
  caused silent port-drop bugs and the current configuration is correct.
