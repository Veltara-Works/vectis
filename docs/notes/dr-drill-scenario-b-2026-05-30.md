# DR Drill (Scenario B) — 2026-05-30

**Type:** Full-rebuild disaster-recovery drill — runbook
[Scenario B](disaster-recovery-runbook.md) ("complete server loss → rebuild on a
new server"). Follow-up to the isolated backup-restore drill
[dr-drill-2026-05-30.md](dr-drill-2026-05-30.md) (P8-H1), which left two
checklist items undrilled: **in-place service health** and **mail send/receive**
after restore.
**Operator:** Veltara Works (agent-assisted)
**Target:** throwaway VPS `sysadmin1001` (BinaryLane id `599937`, `103.100.36.180`,
a-3020 / Singapore) — a separate box from production (`103.100.36.241`).
**Result:** ✅ **PASS** — the two undrilled items are now verified end-to-end on a
clean rebuild. ⚠️ **The drill also exposed that the *documented* `vectis backup
restore` procedure does not work as written on a real install** (Findings B1–B4),
plus a **backup-confidentiality leak** (Finding A) and a **destructive restore that
deletes live secrets** (Finding E). The restore was completed via an
operator-assisted path; the data-restore *logic* is largely sound (one destructive
edge — Finding E), the CLI *orchestration* is not. **All three (A/B/E) are now
fixed in code — see Recommendations.**

---

## Method

A true "complete server loss" simulation, end-to-end on a pristine OS:

1. **Wipe to bare metal.** Rebuilt `sysadmin1001` to a fresh Ubuntu 24.04 image
   via the BinaryLane API (key re-injected; see *SSH note* below).
2. **Fresh customer install.** Installed cosign, then ran the *public* installer
   exactly as a customer would — `curl -fsSL https://get.vectismail.com | bash` —
   which downloaded the **cosign-verified** v0.1.17 binary, bootstrapped Docker,
   and generated configs; then `vectis install` brought up the stack and obtained
   a real Let's Encrypt cert for `mail.sysadmin1001.com`.
3. **Restore a real prod backup.** Took the durable prod archive
   `vectis-20260530-041934.tar.gz.enc` (created by the prod v0.1.17 api container),
   transported it + the `api.backup_encryption_key`, and restored DB + mail + DKIM
   into the fresh stack.
4. **Verify** full-stack health, data census vs prod, real TLS, and an internal
   **send→receive** mail round-trip.
5. **Teardown:** prod-side plaintext shredded; box left running with the restored
   clone (per operator request) for inspection.

**`config.yaml` was intentionally NOT restored** so the rebuilt server keeps its
own hostname (`mail.sysadmin1001.com`) and the valid LE cert. Prod's domains and
mailboxes live in Postgres (virtual, DB-driven), so they restore via the DB dump
without re-rendering postfix/dovecot. (Re-applying prod's `config.yaml` would set
the hostname to `mail.vectismail.com`, whose DNS points at prod, breaking ACME.)

---

## Part 1 — Fresh v0.1.17 install (first full-VPS walkthrough since v0.1.10)

| Check | Result |
|---|---|
| Public installer `get.vectismail.com` → binary + SHA256 | ✓ |
| **cosign keyless signature verified** (P8-H2 supply chain) | ✓ `cosign signature verified` |
| Docker 29.5.2 / Compose v5.1.4 bootstrapped | ✓ |
| `vectis preflight` | ✓ all green (only the cosmetic "3 GB RAM / 4 GB recommended" rounding warning) |
| `vectis install` → stack up | ✓ exit 0, 9/9 services healthy |
| **Real Let's Encrypt cert** for `mail.sysadmin1001.com` | ✓ issuer `O=Let's Encrypt, CN=YR2`, valid 2026-05-30 → 2026-08-28 |
| Empty census (fresh) | ✓ 0 domains / 0 mailboxes / 1 admin |

The v0.1.17 install path works cleanly on a pristine OS. **Note:** dovecot logged
**7 restarts** during the cert-wait window then self-healed to `healthy` — the
v0.1.10 crashloop (finding #1 there) still *occurs* but now *recovers* (the
cert-extractor self-heal from v0.1.11/v0.1.12 works). **Also:** the default fresh
config brings up **9 services, not 11** — `clamav` (RAM-gated) and `webmail` are
config-gated and off by default.

---

## Part 2 — Restore

### What worked (data-restore logic is sound)

Restored into the running stack (Postgres kept up; DB-client services cycled):

| Artifact | Restored | vs prod |
|---|---|---|
| DB: domains | 5 | ✓ match |
| DB: mailboxes | 14 | ✓ match |
| DB: admins | 5 | ✓ match |
| DB: audit_log | 248 | ✓ match |
| DB: api_keys | 6 | ✓ match |
| Mail files | 302 | ✓ match |
| DKIM keys | 5 domains | ✓ |

### What did NOT work — the documented CLI restore (Findings B1–B4)

`vectis backup restore <archive> --confirm`, run on the host as the runbook
Scenario-B step 7 instructs, **failed immediately**:
`database connection failed: ping database: ... lookup postgres ... server misbehaving`.
Root causes (see Findings). The restore was completed via an **operator-assisted
path** mirroring `runRestore`'s effective steps with working connectivity:
decrypt on prod (replicating the AES-256-GCM format) → ship plaintext over the
encrypted SSH channel → load the dump via `docker exec -i vectis-postgres psql -U
postgres` → extract mail/DKIM tars to the host volumes → restart services.

---

## Part 3 — Verification (the two previously-undrilled items)

| Runbook §6 item | Result | Evidence |
|---|---|---|
| **All services healthy after restore** | ✅ | 9/9 containers healthy; `vectis health` all ✓ (postfix/dovecot/rspamd/postgres/valkey/traefik), 0 restarts |
| **Mail send/receive works after restore** | ✅ | Submitted on :587 (AUTH+STARTTLS) → retrieved via IMAP :993 in 2 s; `doveadm INBOX messages=1` |
| Restored mailbox functional | ✅ | `doveadm user ianholt@vectismail.com` → maildir/quota resolved |
| Admin UI over real TLS | ✅ | `https://mail.sysadmin1001.com/admin` → HTTP 200, cert verified (`ssl_verify_result=0`) |
| TLS intact after restore | ✅ | cert still `mail.sysadmin1001.com` (LE YR2) — config.tar deliberately skipped |
| Audit log intact | ✅ | 248 rows |

The internal round-trip exercises the full path: submission → postfix → rspamd →
LMTP → dovecot → Maildir → IMAP retrieval. (External port-25 in/out + DNS/MX/PTR
were out of scope — no DNS points at the throwaway box.)

---

## Findings

### A — Backup leaks secrets via renamed `secrets.yaml.*` copies (HIGH)

The backup excludes only the **exact** filename `secrets.yaml`
(`archiveDirectoryExcluding` with `--exclude secrets.yaml`). But `/etc/vectis/`
accumulates cutover safety copies, and **7 secret-bearing variants are swept into
the archive's `config.tar`**:
`secrets.yaml.pre-comment-2026-05-25`, `secrets.yaml.pre-f3.20260530T041856Z`
(created *today* — current DB passwords, `api.secret`, orchestrator token,
ValidonX service/license keys), `.pre-v0.1.14/15/16/17`, `.bak.20260430`.
The runbook's "secrets.yaml is excluded for security" guarantee — and the
Scenario-A checkbox "secrets.yaml excluded ✓" — only ever verified the
exact-name file. **This affects prod's real backups now.**
**Remediation:** exclude `secrets.yaml*` (glob) — better, back up *only*
`config.yaml` explicitly rather than tarring all of `/etc/vectis`; and operators
should prune the `.bak`/`.pre-*` cruft from `/etc/vectis`.

### B — The documented `vectis backup restore` (host CLI) is non-functional on a real install (HIGH)

The data-transformation logic is correct (proven here + in Scenario A), but the
CLI orchestration cannot run as documented:
- **B1 — DB host unresolvable from the host.** The CLI/Manager connect to the DB
  via hostname `postgres` (the Docker-network service name), which doesn't resolve
  on the host. Fails at the pre-flight ping before doing anything.
- **B2 — restore stops Postgres, then needs it.** `runRestore` does
  `docker compose stop` (all services, incl. Postgres) at step 2, then restores
  the DB via `psql --host postgres` at step 3 — Postgres is down by then.
- **B3 — host `pg_dump`/`psql` assumed.** The Manager shells out to host
  Postgres-client binaries, not installed on a default Ubuntu host.
- **B4 — restore runs as the app user.** `restoreDatabase` connects as
  `cfg.DBUser` (`vectis_api`), which **cannot** restore superuser-owned objects:
  `ERROR: must be owner of extension pgcrypto`. The dump must be loaded by the
  Postgres **superuser** (`postgres`).

Net: backup *create* is wired (runs via `docker exec vectis-api …`; the in-app
scheduler in v0.1.18 handles it), but **restore has no working path** today.
**Remediation:** run restore inside a context where `postgres` resolves (e.g. a
one-off container on the data network, or the orchestrator) using the **superuser**
credential, and don't stop Postgres during the DB load. Then re-validate the
runbook Scenario-B step.

### C — `config.tar` bloat (MEDIUM)

`config.tar` includes ~20 stale `docker-compose.yml.*` / `config.yaml.*` cutover
backups (topology disclosure + archive bloat). Same root cause as A (tarring the
whole `/etc/vectis` dir). Fix by backing up only the canonical files.

### D — Fresh v0.1.17 api container has no durable backups mount (LOW/known)

A fresh v0.1.17 install can't `docker exec vectis-api vectis backup create` to a
durable location either — `/var/vectis/backups` isn't mounted on the api
container (the F1 finding). Fix lands in v0.1.18 (mount in-template).

### E — Restore deletes `/etc/vectis/secrets.yaml`, leaving the install unbootable (HIGH)

Found *after* A/B, during post-restore re-validation on the box — hence the later
letter; severity is **HIGH**. `restoreDirectory` wipes the target directory
(`os.RemoveAll`) before extracting the archive. Because `secrets.yaml` is
(correctly) **excluded from every backup** for confidentiality (Finding A), it is
never inside `config.tar` — so restoring the config archive over `/etc/vectis`
**deletes the operator's live `secrets.yaml`**. On the rebuilt box this left the
api/orchestrator crashlooping (no DB password, no `api.secret`): a DR restore that
*destroys the very credential it needs to come back up*. **A and E compound** — A
makes secrets absent from the archive, E then deletes the on-disk copy during
restore.
**Remediation (fixed this branch):** `restoreDirectory` gained a `preserveGlobs`
parameter; the config restore passes `secrets.yaml*`, which is stashed to a temp
dir before the wipe and copied back (mode-preserving) after extract. Guarded by
unit test `TestRestoreDirectoryPreservesSecrets`. *Limitation:* `copyFilePreserve`
preserves file mode but not uid/gid — fine on the single-operator prod box
(everything `johnsmith`-owned), but worth noting if a future install runs services
as a different user.

### Observations (non-defects)

- **BL inter-VM filter.** BinaryLane silently drops ports 22/25 *between its own
  customer VMs* regardless of per-instance firewall rules. A fresh OS defaults
  `sshd` to 22 → unreachable from a BL-VM jump host. The first rebuild left SSH on
  22 (timeout); a second rebuild with cloud-init relocated `sshd` to 54709
  (handling the Ubuntu 24.04 socket-activation quirk: disable `ssh.socket`, set
  `Port` in `sshd_config`, enable `ssh.service`). Relevant if a DR rebuild's only
  reachable origin is another BL VM.
- **Stale manifest.** `/var/vectis/backups/manifest.json` on prod references 3
  already-pruned archives (cosmetic; restore reads the file path directly).

---

## Drill checklist (runbook §6) — now fully exercised

- [x] Latest backup within RPO window
- [x] Backup archive passes integrity check (full restore)
- [x] Restore completes without errors *(via operator-assisted path — see Finding B)*
- [x] **All services healthy after restore** *(was undrilled)*
- [x] **Mail send/receive works after restore** *(was undrilled)*
- [x] Admin UI accessible and functional
- [x] Audit log intact
- [ ] Deliverability checks pass for all domains — N/A (no DNS points at the box)
- [x] `secrets.yaml` (exact name) excluded — **but see Finding A** (variants leak)

---

## Recommendations (priority order)

> **Status — 2026-05-30:** Findings **A, B, and E are fixed** on branch
> `dr-scenario-b-2026-05-30` (this report ships alongside them). The fixes land on
> `main` via PR and reach prod with the next release; until then prod still runs the
> broken restore path, so the manual fallback in the runbook still applies.

1. **Finding A (HIGH) — FIXED.** Glob-exclude `secrets.yaml*` closes the leak.
   Still do: prune the `.bak`/`.pre-*` cruft from `/etc/vectis`, and treat A as a
   **gate before enabling any off-host backup copies** (runbook §5).
2. **Finding B (HIGH) — FIXED.** Host restore now loads the dump via
   `docker exec … psql -U postgres` (superuser, Postgres kept up) on a nil-pool CLI
   path. Re-validate the fixed *CLI* path end-to-end on a clean rebuild (this drill
   proved the data logic + the rebuild, not yet the repaired CLI).
3. **Finding E (HIGH) — FIXED.** Restore preserves `secrets.yaml*` across the
   config-dir replace. Re-validate on a real box that `secrets.yaml` survives a
   restore (pending — needs a working `secrets.yaml` staged first).
4. **Findings C/D** — fold into the v0.1.18 backup work.
5. Re-run this Scenario-B drill once the fixes are deployed, to confirm the *CLI*
   path end-to-end.
