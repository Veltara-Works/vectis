# Copilot review guidance

This file tells GitHub Copilot how to review pull requests in this repository. Copy this file verbatim to other repos in the same family; only the **Repo-specific notes** block at the bottom needs per-repo editing.

---

## What we want from a Copilot review

Treat reviews like a senior engineer's — **terse, actionable, opinionated**. A Copilot review should:

- Surface bugs, security issues, and regressions a human reviewer might miss in a long diff.
- Flag architectural drift (mixing concerns, leaking abstractions across layer boundaries).
- Catch hidden state changes — anything that affects shared infrastructure, prod data, billing, auth, or audit trails.
- Note when test coverage is missing for new behavior **that warrants a test**. Don't ask for tests on trivial refactors, doc changes, or lockfile bumps.

What we **do NOT** want:

- Style nits — formatters and linters are wired into CI; don't comment on indentation, whitespace, or operator spacing.
- Trivial naming suggestions ("consider renaming `x` to `xValue`") unless the existing name is genuinely misleading.
- "Consider adding a comment here" suggestions. Comments are deliberately sparse in this codebase; only flag missing comments where a non-obvious WHY would help a future reader.
- Re-explaining what the code does in your review summary. Assume the reviewer can read.
- Speculation about hypothetical future requirements ("you might want to add caching later"). Review what's in the diff, not what isn't.
- Suggestions to add try/catch, defensive nulls, or input validation for code paths that already trust their callers (internal-only services). Only flag missing defenses at system boundaries (HTTP handlers, message queues, external API responses).

---

## Read the PR description first

The PR description is the author's intent — the diff is the implementation. **Always read the PR body before reviewing the diff.**

If the PR is lockfile-only (e.g. `package-lock.json`, `composer.lock`, `yarn.lock`, `Cargo.lock`):

- The diff is auto-generated. Don't try to "review" the lockfile content.
- The meaningful review surface is the **PR description**: what advisories does it close, what versions are bumped, what's the risk justification, what's been verified.
- If the description is missing security/risk justification, that's the comment to make. If the description has it, the review is "looks good — security justification is documented."

If the PR is a doc-only change, skip suggestions about implementation patterns. Review for clarity, accuracy, and outdated cross-references.

---

## Security review focus areas

Treat these as load-bearing. A miss here is an actual incident vector:

1. **Authentication / authorization bypass** — any new endpoint must have an auth middleware (or be explicitly public with a comment saying why). Any new admin-scoped route must reject non-admin actors.
2. **SQL injection / template injection / command injection** — any string concatenated into a query, shell command, or template is suspect unless using parameterized APIs.
3. **Cross-tenant leakage** — in multi-tenant code, every query that reads tenant data must scope by tenant ID. A query without a tenant scope is a bug.
4. **Audit trail gaps** — security-relevant mutations (auth changes, billing, key issuance, admin user edits) must call the audit service. Non-security state changes (UX state, view counters) should NOT pollute the audit log.
5. **Secrets in logs / responses / commit history** — passwords, API keys, tokens, JWTs, signing keys must never appear in logs, error messages, audit metadata, or test fixtures. Hashed passwords are also sensitive (the bcrypt cost prefix `$2y$` is a tell).
6. **Insecure defaults** — config switches that default to insecure (auth off, signature verification disabled, TLS verify off) should fail loudly, not silently.
7. **Webhook / signature verification** — inbound webhooks must verify signatures before any state-affecting work. Outbound webhooks must sign their payloads.

---

## Migration safety

Database migrations land via deploy and aren't trivially revertible. Flag:

- `ALTER TABLE` on a populated table without a chunked / online strategy.
- Adding a `NOT NULL` column without a default or a backfill plan.
- Dropping a column or table without a transitional read-and-drop sequence.
- Migrations that aren't reversible (`down()` empty or non-functional).
- `DROP`, `TRUNCATE`, `DELETE` without a `WHERE` — these should never appear in a migration outside of explicit tear-down for fresh installs.

If the migration is additive and small (new table, new nullable column, new index), no comment needed.

---

## API contracts

If a route, endpoint shape, response envelope, or webhook payload changes:

- Flag any breaking change to a documented contract. Documented = appears in OpenAPI, in `docs/`, or in a public SDK.
- Versioning: API versions in URLs (`/v1/...`) should not have their contracts mutated; new behavior goes to `/v2/...` or via opt-in headers.
- Inbound and outbound webhook payloads are public contracts the moment a third party consumes them.

---

## Commit and PR hygiene

Don't comment on these unless something is genuinely off:

- Commit messages should describe the **why**, not the what. The `what` is in the diff.
- PR titles should be short (under 70 chars). Detail goes in the body.
- Branch names: `feat/...`, `fix/...`, `chore/...`, `docs/...` are conventional.
- **Never suggest adding `Co-Authored-By: Claude` (or any other AI-attribution trailer)** to commit messages, PR bodies, or release notes. AI involvement may be mentioned in marketing copy; commit metadata is not the place.

---

## Tone and format of review comments

- One sentence per comment is usually enough. Two if you need to point at a fix.
- Use code-suggestion blocks for concrete one-line fixes.
- Group related findings into one comment rather than scattering five identical suggestions across a file.
- If a finding is severity-relevant, lead with severity: "**Bug:** ...", "**Security:** ...", "**Architecture:** ...". If unprefixed, the reader assumes "nit."
- Prefer "Consider X because Y" over "You should X." We treat reviews as recommendations, not commands.
- Don't apologize, don't hedge with "I might be wrong but..." — say what you think, the author can push back.

---

## Repo-specific notes

> **Edit this section per repo.** Everything above is shared boilerplate across our repositories.

- This repo is **`Veltara-Works/vectis`** — a self-hosted mail server (Postfix + Dovecot + Rspamd + Traefik + Postgres + Valkey + ClamAV). Go + Chi backend, React + TypeScript admin UI, deployed via Docker Compose. Currently live in production at `mail.vectismail.com`.
- **Architecture v1.4 is frozen** — start with `AGENTS.md`, then `docs/architecture/ADR_Index.md` (25 binding ADRs) and `docs/spec/` (Specs A–G). Don't suggest architectural changes without an ADR; flag PRs that drift from the frozen architecture.
- **Domains live in Postgres, not config files.** Postfix and Dovecot read domain/mailbox/alias data via direct SQL lookups (`pgsql_virtual_*.cf`). Don't suggest writing per-domain Postfix maps or templating per-domain Dovecot config — entity changes must not require a container reload.
- **Three Postgres users by privilege:** `vectis_postfix` (RO), `vectis_dovecot` (RO), `vectis_api` (full). If a new query under `internal/api` or `internal/orchestrator` is using a postfix/dovecot user, or postfix/dovecot SQL config is using vectis_api, that's a bug.
- **The orchestrator is the ONLY container with the Docker socket.** Never suggest giving `/var/run/docker.sock` to api, postfix, dovecot, or anything else. New container-management code goes through `internal/orchestrator/docker.go` (`DockerManager`).
- **Forward-only migrations.** Migrations live under `migrations/` and are embedded via golang-migrate in the Go binary. `down()` is intentionally non-functional; rollback path is `pg_dump` snapshot restore via the orchestrator. Don't ask authors to write reversible `down()` steps; do flag migrations that risk locking a populated table (per the Migration safety section above).
- **Bind-mount inode gotcha:** any code path that atomically rewrites a host file bind-mounted into a container (e.g. `/var/vectis/generated/postfix/main.cf`) must trigger a `docker restart` of that container — `postfix reload` / SIGHUP / `compose up -d` is not enough because the container holds the original inode. Self-heal in `internal/orchestrator/compose_selfheal.go` handles this for `RegenerateConfigs`; flag any new code that edits bind-mounted configs without going through that path.
- **`internal: true` Docker networks silently drop `ports:` directives.** If a PR adds a new compose service that needs to publish a host port, verify it isn't on an internal-only network. Same class of bug bit Postgres healthcheck and the postfix/dovecot mail ports historically.
- **Engine templates are source-of-truth.** Anything under `internal/engine/templates/` (compose, postfix, dovecot, rspamd, etc.) is rendered by the engine into `/var/vectis/generated/...` at install + Plan/Apply Phase 3.6 + self-heal time. Don't suggest editing rendered files directly. Template content changes should be pinned by a test in `internal/engine/engine_test.go` (the existing `TestPostfixMainCF` / `TestDovecotSQL` style).
- **Plan/Apply is the customer upgrade path.** New release-relevant code (compose structure, service set, config defaults) needs to land via the orchestrator's Plan/Apply pipeline (see ADRs + `internal/orchestrator/`). PRs that change runtime config without a corresponding migration through Plan/Apply (Phase 3.5 compose rewrite + Phase 3.6 config regen + self-heal restart) will silently break existing installs on Apply — flag them.
- **License / FeatureGate is fail-CLOSED.** Free-tier installs must deny Pro/Enterprise endpoints (was a real bypass bug fixed at 5efacff). Any new gated endpoint should call the FeatureGate; missing the gate is a security issue, not a UX one.
- **Webhook emitters:** Vectis emits 7 `mail.*` events to ValidonX. Inbound auth uses `X-API-Key` (path-2 ADR-041), NOT bearer tokens — `/v1/auth/login` was retired. Real-envelope tests are required for any change to webhook payload shape (mock-from-our-struct tests miss wire-shape divergence).
- **Single-tenant today, multi-tenant Phase 4.** Don't ask authors to add per-tenant scoping yet; flag instead if new code makes assumptions that would block the Phase 4 multi-tenant pivot (e.g. global counters that should become per-tenant, hardcoded admin-email ownership).
- **`docs/notes/validonx/`** holds in-flight ValidonX correspondence kept locally — intentionally untracked. Don't flag missing tests / missing docs cross-references for files in that directory.
- **Customer-facing release artifacts:** binary + 8 images publish to `ghcr.io/veltara-works/vectis-*` and `dl.vectismail.com` on tag push via `.github/workflows/release.yml`. `releases-stable.json` and `releases-rc.json` are channel manifests — `:latest` is gated to stable tags only. Flag any PR that risks demoting a stable tag from an rc cut.
