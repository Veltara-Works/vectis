# E. CLI Input/Output Contracts

**Status:** DRAFT — For review with Copilot before integration into Spec v1.1  
**Prepared by:** Claude (round 5)  
**Complements:** Vectis Architecture v1.3, Implementation Spec v1.0

---

## E.1 Overview

The Vectis CLI is a single Go binary that serves dual purposes:
- `vectis serve` → runs the Go API server
- All other subcommands → CLI operations

The CLI outputs human-readable text by default. All commands support a `--json` flag for structured JSON output (for scripting and CI/CD integration).

Exit codes are consistent across all commands:
- `0` = success
- `1` = failure (details in output)
- `2` = validation error or invalid input

---

## E.2 Installation Commands

### vectis preflight

Runs pre-flight checks without making any changes to the system.

| Property | Value |
|----------|-------|
| **Input** | None (reads system state). Optional: `--config path/to/config.yaml` to validate a pre-written config |
| **Output (success)** | "Ready to install Vectis" + system summary (OS, CPU, RAM, disk, ports, DNS) |
| **Output (failure)** | Per-check results: PASS/FAIL with actionable fix instructions for each failure |
| **Side effects** | None (read-only) |
| **Exit code 0** | All checks pass |
| **Exit code 1** | One or more checks failed |

**Example output (success):**

```
Vectis Pre-Flight Check
=======================
OS:          Ubuntu 24.04 LTS          ✓
CPU:         4 vCPU                    ✓
RAM:         8 GB                      ✓
Disk:        80 GB (72 GB free)        ✓
IPv4:        203.0.113.10              ✓
IPv6:        2001:db8::1               ✓
Hostname:    mail.example.com          ✓
DNS A:       203.0.113.10 → matches    ✓
DNS AAAA:    2001:db8::1 → matches     ✓
Port 25:     available                 ✓
Port 80:     available                 ✓
Port 443:    available                 ✓
Port 587:    available                 ✓
Port 993:    available                 ✓
SMTP out:    port 25 reachable         ✓
Docker:      not installed (will install) ✓

Ready to install Vectis.
Run: vectis install
```

**Example output (failure):**

```
Vectis Pre-Flight Check
=======================
OS:          Ubuntu 24.04 LTS          ✓
CPU:         1 vCPU                    ✗ Minimum 2 vCPU required
RAM:         2 GB                      ✗ Minimum 4 GB recommended (2 GB minimum without ClamAV)
Port 80:     in use by apache2         ✗ Stop apache2: sudo systemctl stop apache2 && sudo systemctl disable apache2
SMTP out:    port 25 blocked           ✗ Contact your hosting provider to unblock outbound SMTP (port 25)

2 checks failed, 2 warnings. Fix the above issues before installing.
```

---

### vectis install

Performs full installation on a fresh host.

| Property | Value |
|----------|-------|
| **Input** | Interactive prompts: hostname, admin email, initial domain. Or `--config path/to/config.yaml --secrets path/to/secrets.yaml` for unattended install |
| **Output** | Progress per step; final: admin URL + initial admin credentials |
| **Side effects** | Installs Docker, generates configs, pulls images, starts containers, runs migrations |
| **Exit code 0** | Install complete, all health checks pass |
| **Exit code 1** | Install failed (error message includes cleanup instructions) |

**Example output:**

```
Installing Vectis...

[1/8] Installing Docker Engine + Compose... done
[2/8] Configuring Docker (log rotation, IPv6)... done
[3/8] Generating config.yaml... done
[4/8] Generating secrets.yaml... done
[5/8] Generating initial docker-compose.yml... done
[6/8] Pulling container images... done (4m 12s)
[7/8] Starting services... done
[8/8] Running health checks... all services healthy

═══════════════════════════════════════════
  Vectis is ready!

  Admin URL:   https://mail.example.com/admin
  Admin email: admin@example.com
  Password:    Kj7#mP9$xR2q

  IMPORTANT: Change this password immediately.
  
  Next steps:
  1. Log in to the admin panel
  2. Add your DNS records (shown in Deliverability section)
  3. Create your first mailbox
═══════════════════════════════════════════
```

---

## E.3 Status & Health Commands

### vectis status

| Property | Value |
|----------|-------|
| **Input** | None |
| **Output** | Per-service: name, status, uptime, CPU %, memory usage |
| **Side effects** | None |
| **Exit code 0** | All services healthy |
| **Exit code 1** | One or more services unhealthy or stopped |

**Example output:**

```
Vectis Status
═════════════
Service        Status     Uptime      CPU     Memory
─────────────────────────────────────────────────────
postfix        healthy    14d 3h      0.2%    48 MB
dovecot        healthy    14d 3h      0.1%    92 MB
rspamd         healthy    14d 3h      1.4%    312 MB
clamav         healthy    14d 3h      0.0%    1.2 GB
postgres       healthy    14d 3h      0.3%    156 MB
valkey         healthy    14d 3h      0.1%    42 MB
api            healthy    14d 3h      0.2%    38 MB
admin-ui       healthy    14d 3h      0.0%    12 MB
traefik        healthy    14d 3h      0.1%    45 MB
orchestrator   healthy    14d 3h      0.0%    28 MB
```

---

### vectis health

| Property | Value |
|----------|-------|
| **Input** | Optional: `--service NAME` for single service detail |
| **Output** | Per-service health with check details and response times |
| **Side effects** | None |
| **Exit code 0** | All healthy |
| **Exit code 1** | One or more unhealthy |

---

## E.4 Configuration Commands

### vectis config validate

| Property | Value |
|----------|-------|
| **Input** | Reads `config.yaml` and `secrets.yaml` from default location (`/etc/vectis/`) or `--config-dir PATH` |
| **Output (valid)** | "Configuration is valid" |
| **Output (invalid)** | List of errors with locations and fix suggestions |
| **Side effects** | None |
| **Exit code 0** | Valid |
| **Exit code 1** | One or more validation errors |

**Example error output:**

```
Configuration validation failed:

  config.yaml:14  Invalid domain name: "not a domain"
                  Domain must be a valid FQDN (e.g., example.com)

  config.yaml:28  Unknown ClamAV profile: "turbo"
                  Valid profiles: none, dev, small, production, enterprise

  secrets.yaml:   Missing required key: db_password
                  Add db_password to secrets.yaml

3 errors found.
```

---

### vectis config diff

| Property | Value |
|----------|-------|
| **Input** | Reads config.yaml, secrets.yaml, DB state, current generated configs |
| **Output** | Per-file diff; per-service action summary |
| **Side effects** | None (read-only) |
| **Exit code 0** | No changes pending |
| **Exit code 1** | Changes pending (diff shown) |
| **Exit code 2** | Validation error in config |

**Example output:**

```
Configuration changes detected:

  postfix/main.cf:
    - smtpd_tls_security_level = may
    + smtpd_tls_security_level = encrypt

  rspamd/local.d/actions.conf:
    - reject = 15;
    + reject = 12;

Service actions required:
  postfix:   reload
  rspamd:    reload
  dovecot:   no change
  clamav:    no change
  traefik:   no change

Run 'vectis config apply' to apply these changes.
```

---

### vectis config apply

| Property | Value |
|----------|-------|
| **Input** | Reads config.yaml, secrets.yaml, DB state |
| **Output** | Changes applied; per-service actions taken |
| **Side effects** | Regenerates config files; triggers reloads/restarts as needed |
| **Exit code 0** | All changes applied successfully |
| **Exit code 1** | Partial failure (some reloads failed; details in output) |
| **Exit code 2** | Config validation failed; no changes made |
| **Flags** | `--dry-run` (equivalent to `vectis config diff`) |

---

## E.5 Update Commands

### vectis update plan

| Property | Value |
|----------|-------|
| **Input** | None (checks upstream registry for new images) |
| **Output** | Structured plan: version changes, config changes, migrations, warnings |
| **Side effects** | Stores plan in orchestrator state |
| **Exit code 0** | Plan generated (may be "no updates available") |
| **Exit code 1** | Cannot generate plan (network error, registry unreachable) |

**Example output:**

```
Update plan generated:

  Container changes:
    postfix:   1.2.0 → 1.3.0
    rspamd:    3.8.0 → 3.9.0
    api:       0.4.0 → 0.5.0

  Database migrations:
    042_add_quota_tracking (non-destructive)
    043_add_audit_log_indexes (non-destructive)

  Config changes:
    postfix/main.cf will be regenerated

  No destructive operations.

  Run 'vectis update apply' to execute this plan.
  Plan expires if system state changes before apply.
```

---

### vectis update apply

| Property | Value |
|----------|-------|
| **Input** | Requires a prior plan (or `--force` to plan + apply in one step) |
| **Output** | Step-by-step progress |
| **Side effects** | Full update cycle per orchestrator state machine |
| **Exit code 0** | Update successful |
| **Exit code 1** | Update failed, automatic rollback succeeded (previous state restored) |
| **Exit code 2** | Update failed, rollback ALSO failed (**CRITICAL** — manual intervention needed) |

**Example output:**

```
Applying update plan...

  [1/6] Validating configuration... passed
  [2/6] Taking database snapshot... done (snapshot-20260328-120000.sql)
  [3/6] Applying database migrations... done (2 migrations)
  [4/6] Pulling new container images... done (1m 34s)
  [5/6] Restarting services... done
  [6/6] Running health checks... all healthy

Update applied successfully.
  postfix:   1.2.0 → 1.3.0
  rspamd:    3.8.0 → 3.9.0
  api:       0.4.0 → 0.5.0
```

**Example failure output:**

```
Applying update plan...

  [1/6] Validating configuration... passed
  [2/6] Taking database snapshot... done
  [3/6] Applying database migrations... done
  [4/6] Pulling new container images... done
  [5/6] Restarting services... done
  [6/6] Running health checks... FAILED
        rspamd: unhealthy after 60s (exit code 1)

  Automatic rollback initiated...
  [R1/3] Restoring database... done
  [R2/3] Reverting containers... done
  [R3/3] Health checks... all healthy

  Update rolled back successfully. System restored to previous state.
  Check rspamd logs: vectis logs rspamd
```

---

### vectis update rollback

| Property | Value |
|----------|-------|
| **Input** | None (rolls back to last snapshot) |
| **Output** | Rollback progress |
| **Side effects** | Restores DB snapshot, reverts container images |
| **Exit code 0** | Rollback successful |
| **Exit code 1** | Rollback failed (**CRITICAL**) |

---

### vectis update self

| Property | Value |
|----------|-------|
| **Input** | None (checks registry for new orchestrator + API images) |
| **Output** | Progress; restart notice |
| **Side effects** | Replaces orchestrator and API containers (bypasses orchestrator state machine) |
| **Exit code 0** | Self-update successful |
| **Exit code 1** | Self-update failed, reverted to previous images |

---

## E.6 Data Management Commands

### vectis backup create

| Property | Value |
|----------|-------|
| **Input** | Optional: `--output /path/to/backup.tar.gz` (default `/var/vectis/backups/vectis-YYYYMMDD-HHMMSS.tar.gz`); `--db-host <host>` dumps the DB over TCP from a directly-reachable Postgres (requires `pg_dump` on the host) instead of the default `docker exec` into the `vectis-postgres` container |
| **Output** | Progress per component; final: backup path + size |
| **Side effects** | Creates backup archive |
| **Exit code 0** | Backup complete |
| **Exit code 1** | Backup failed (partial file cleaned up) |

**Example output:**

```
Creating backup...
  [1/4] Database dump... done (12 MB)
  [2/4] Mail data... done (2.3 GB, 4,812 files)
  [3/4] Configuration... done
  [4/4] DKIM keys... done

Backup saved: /var/vectis/backups/vectis-20260328-120000.tar.gz (2.4 GB)
```

---

### vectis backup restore

| Property | Value |
|----------|-------|
| **Input** | Path to backup archive (required). `--confirm` flag required (destructive operation) |
| **Output** | Restore progress; service restart notification |
| **Side effects** | Stops all services, replaces all data, restarts services |
| **Exit code 0** | Restore complete, all services healthy |
| **Exit code 1** | Restore failed |

---

### vectis domain add

| Property | Value |
|----------|-------|
| **Input** | `--name example.com` (required). Optional: `--spam-threshold 12.0`, `--max-mailboxes 50`, `--no-dkim` |
| **Output** | Domain created; DKIM DNS record to add; deliverability reminder |
| **Side effects** | Inserts domain in Postgres; generates DKIM keys; triggers Rspamd reload |
| **Exit code 0** | Domain added |
| **Exit code 1** | Error (domain already exists, invalid name, etc.) |

**Example output:**

```
Domain example.com created.

Add this DNS TXT record for DKIM:
  Name:  202603._domainkey.example.com
  Value: v=DKIM1; k=rsa; p=MIIBIjANBgkqh...

Also ensure these DNS records exist:
  SPF:   v=spf1 mx a ip4:203.0.113.10 -all
  DMARC: v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com

Check deliverability: vectis domain check example.com
```

---

### vectis domain list

| Property | Value |
|----------|-------|
| **Input** | Optional: `--active-only`, `--json` |
| **Output** | Domain list with status and mailbox count |
| **Side effects** | None |
| **Exit code 0** | Always |

---

### vectis domain remove

| Property | Value |
|----------|-------|
| **Input** | `--name example.com` (required), `--confirm` (required — destructive) |
| **Output** | Removal confirmation; reminder to run `vectis config apply` |
| **Side effects** | Deletes domain from Postgres. Refuses (exit 1) if mailboxes or aliases still exist |
| **Exit code 0** | Domain removed |
| **Exit code 1** | Error (not found, mailboxes/aliases present, `--confirm` omitted) |
| **Exit code 2** | `--name` missing |

---

### vectis mailbox add

| Property | Value |
|----------|-------|
| **Input** | `--email user@example.com` (required). `--password` (prompted securely if not provided). Optional: `--quota 2048`, `--display-name "User Name"` |
| **Output** | Mailbox created confirmation |
| **Side effects** | Inserts mailbox in Postgres; creates Maildir on disk |
| **Exit code 0** | Mailbox added |
| **Exit code 1** | Error (domain not found, mailbox exists, validation failed) |

---

### vectis mailbox list

| Property | Value |
|----------|-------|
| **Input** | Optional: `--domain example.com` (default: all domains), `--json` |
| **Output** | Mailbox list (email, quota, active, sending status, created) |
| **Side effects** | None |
| **Exit code 0** | Always |
| **Exit code 1** | Error (named domain not found) |

---

### vectis mailbox remove

| Property | Value |
|----------|-------|
| **Input** | `--email user@example.com` (required), `--confirm` (required — destructive) |
| **Output** | Removal confirmation |
| **Side effects** | Deletes mailbox metadata from Postgres. The on-disk maildir is Dovecot-owned and left untouched |
| **Exit code 0** | Mailbox removed |
| **Exit code 1** | Error (domain/mailbox not found, `--confirm` omitted) |
| **Exit code 2** | `--email` missing or malformed |

---

### vectis logs

| Property | Value |
|----------|-------|
| **Input** | Service name (required): postfix, dovecot, rspamd, clamav, postgres, valkey, api, admin-ui, traefik, orchestrator. Flags: `--tail N`, `--since TIMESTAMP`, `--follow` |
| **Output** | Log lines from specified service |
| **Side effects** | None |
| **Exit code 0** | Always |

---

## E.7 Global Flags

All commands support:

| Flag | Purpose |
|------|---------|
| `--json` | Output structured JSON instead of human-readable text |
| `--quiet` | Suppress non-essential output (only errors and final result) |
| `--verbose` | Show detailed debug output |
| `--config-dir PATH` | Override default config directory (default: `/etc/vectis/`) |
| `--help` | Show help for the command |
| `--version` | Show Vectis CLI version |
