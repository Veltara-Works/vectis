# Vectis Mail — Disaster Recovery Runbook

**Status:** Active
**Created:** 2026-04-03
**Owner:** Veltara Works
**Audience:** System administrators, on-call operators
**Last tested:** 2026-05-30 — isolated backup-restore drill PASSED (a real prod
backup restored to a working system in a throwaway sandbox). See
[dr-drill-2026-05-30.md](dr-drill-2026-05-30.md). Two backup-durability gaps
found — see the ⚠️ note below. Next: an in-place / full-rebuild (Scenario B) drill.

---

## 1. Recovery Objectives

| Metric | Target | Notes |
|--------|--------|-------|
| **RPO** (Recovery Point Objective) | 24 hours | Based on default daily backup schedule (`0 3 * * *`). Configurable via `config.yaml` `backup.schedule`. |
| **RTO** (Recovery Time Objective) | 1 hour | Full restore from backup on a prepared server. Excludes DNS propagation time. |
| **MTTR** (Mean Time to Repair) | 2 hours | Includes diagnosis, restore, and verification. |

**Note:** RPO can be reduced to as low as 1 hour by adjusting the backup cron schedule. For critical deployments, consider `0 * * * *` (hourly backups) with a shorter retention period.

---

> ⚠️ **Open gaps from the 2026-05-30 drill (fix before relying on this runbook):**
> 1. **Backups are not persisted.** `/var/vectis/backups` is not mounted on the
>    `vectis-api` container, so backups land on its ephemeral layer and are lost
>    on the next `compose down/up` (every cutover). The paths in §8 assume
>    persistence that isn't wired yet. Add a durable mount for the api service.
> 2. **Scheduled backups are off** (`config.yaml backup.enabled: false`). The
>    24h RPO is not currently being met. Enable — but only after gap #1.
>
> See [dr-drill-2026-05-30.md](dr-drill-2026-05-30.md) for details + remediation.

---

## 2. What's Protected

### Included in backups
- **PostgreSQL database** — all tables (domains, mailboxes, aliases, admins, sessions, audit log, orchestrator history, etc.)
- **Mail data** — all Maildir directories at `/var/vectis/mail/`
- **Configuration** — `/etc/vectis/config.yaml` (secrets.yaml is excluded for security)
- **DKIM private keys** — `/var/vectis/dkim/`

### NOT included in backups (manual recovery required)
- **`/etc/vectis/secrets.yaml`** — contains DB passwords, API secret, orchestrator token, backup encryption key. Must be backed up separately via secure out-of-band mechanism (e.g., encrypted vault, password manager).
- **Docker images** — pulled from GHCR on install; not backed up.
- **TLS certificates** — re-provisioned automatically by Traefik (ACME) on startup; the `cert-extractor` sidecar then splits Traefik's `acme.json` into mail-stack PEM files and HUPs Postfix/Dovecot on rotation. No backup of cert material is needed; both certificate chains rebuild from a clean ACME challenge.
- **Fail2ban state** — jail state is ephemeral; rebuilds on restart.

---

## 3. Backup Verification

### 3.1 Verify backup exists and is recent

```bash
vectis backup list
```

Expected output: at least one backup within the RPO window (24 hours by default).

### 3.2 Verify backup integrity

```bash
# For unencrypted backups:
tar -tzf /var/vectis/backups/vectis-YYYYMMDD-HHMMSS.tar.gz | head -20

# Verify database dump is present:
tar -tzf /var/vectis/backups/vectis-YYYYMMDD-HHMMSS.tar.gz | grep database.sql
```

For encrypted backups (`.tar.gz.enc`), integrity can only be verified by attempting a restore to a test environment.

### 3.3 Scheduled verification (recommended)

Add a weekly cron job to verify the most recent backup:

```bash
# /etc/cron.weekly/vectis-backup-verify
#!/bin/bash
LATEST=$(ls -t /var/vectis/backups/vectis-*.tar.gz 2>/dev/null | head -1)
if [ -z "$LATEST" ]; then
    echo "ALERT: No Vectis backup files found" | logger -t vectis-backup
    exit 1
fi
AGE=$(( ($(date +%s) - $(stat -c %Y "$LATEST")) / 3600 ))
if [ "$AGE" -gt 48 ]; then
    echo "ALERT: Most recent Vectis backup is ${AGE}h old (>48h)" | logger -t vectis-backup
    exit 1
fi
echo "OK: Vectis backup ${LATEST} is ${AGE}h old" | logger -t vectis-backup
```

### 3.4 Full backup validation procedure (monthly)

Run this procedure monthly to confirm backups are fully restorable:

```bash
# 1. Create a temporary directory for test restore.
TESTDIR=$(mktemp -d /tmp/vectis-validate-XXXXXX)
LATEST=$(ls -t /var/vectis/backups/vectis-*.tar.gz 2>/dev/null | head -1)

# 2. Extract the archive.
tar -xzf "$LATEST" -C "$TESTDIR"

# 3. Verify all expected components are present.
echo "=== Checking archive contents ==="
for FILE in database.sql; do
    if [ -f "$TESTDIR/$FILE" ]; then
        echo "  [OK] $FILE ($(wc -c < "$TESTDIR/$FILE") bytes)"
    else
        echo "  [FAIL] $FILE missing!"
    fi
done

for ARCHIVE in mail-data.tar config.tar dkim.tar; do
    if [ -f "$TESTDIR/$ARCHIVE" ]; then
        COUNT=$(tar -tf "$TESTDIR/$ARCHIVE" 2>/dev/null | wc -l)
        echo "  [OK] $ARCHIVE ($COUNT entries)"
    else
        echo "  [WARN] $ARCHIVE missing (may be empty if no data)"
    fi
done

# 4. Validate the SQL dump is parseable.
echo "=== Validating database dump ==="
if head -5 "$TESTDIR/database.sql" | grep -q "PostgreSQL"; then
    TABLES=$(grep -c "CREATE TABLE" "$TESTDIR/database.sql" || true)
    echo "  [OK] Valid PostgreSQL dump ($TABLES tables)"
else
    echo "  [FAIL] database.sql does not appear to be a valid dump"
fi

# 5. Clean up.
rm -rf "$TESTDIR"
echo "=== Validation complete ==="
```

**Expected output for a healthy backup:**
- `database.sql` present and valid PostgreSQL dump
- `mail-data.tar` present with Maildir entries (may be empty on fresh install)
- `config.tar` present with config files
- `dkim.tar` present with DKIM keys

**For encrypted backups** (`.tar.gz.enc`): Decrypt first using the backup encryption key:
```bash
# Decryption requires the vectis binary or a compatible AES-256-GCM decryptor.
# The simplest validation is a full test restore:
vectis backup restore "$LATEST" --confirm  # On a TEST server only!
```

---

## 4. Disaster Recovery Procedures

### Scenario A: Database corruption (services running, data corrupted)

**Symptoms:** API errors, missing data, constraint violations in logs.

**Procedure:**

1. **Confirm the issue:**
   ```bash
   vectis health
   docker compose logs vectis-api --tail=50
   ```

2. **Stop services to prevent further writes:**
   ```bash
   docker compose stop
   ```

3. **Restore from latest backup:**
   ```bash
   vectis backup restore /var/vectis/backups/vectis-YYYYMMDD-HHMMSS.tar.gz --confirm
   ```

4. **Verify recovery:**
   ```bash
   vectis health
   vectis status
   ```

5. **Check mail flow:**
   - Send a test email to a mailbox
   - Verify delivery in Maildir
   - Check deliverability dashboard

**Expected duration:** 15-30 minutes.

---

### Scenario B: Complete server loss (rebuild on new server)

**Symptoms:** Server unreachable, hardware failure, hosting provider outage.

**Prerequisites:**
- A new server meeting Vectis requirements (Ubuntu 24.04 LTS, Docker Engine)
- A copy of the most recent backup archive
- A copy of `/etc/vectis/secrets.yaml` (from secure out-of-band storage)
- DNS access to update records

**Procedure:**

1. **Provision new server:**
   ```bash
   # Install Docker Engine
   curl -fsSL https://get.docker.com | sh

   # Install Vectis binary
   # (download from GHCR or copy from backup)
   ```

2. **Run preflight:**
   ```bash
   vectis preflight
   ```

3. **Restore secrets.yaml:**
   ```bash
   mkdir -p /etc/vectis
   # Copy secrets.yaml from secure storage
   chmod 0600 /etc/vectis/secrets.yaml
   ```

4. **Run install:**
   ```bash
   vectis install
   ```

5. **Stop services before restore:**
   ```bash
   docker compose stop
   ```

6. **Copy backup archive to new server:**
   ```bash
   scp -P <your-ssh-port> backup-server:/path/to/vectis-YYYYMMDD-HHMMSS.tar.gz /var/vectis/backups/
   ```

7. **Restore from backup:**
   ```bash
   vectis backup restore /var/vectis/backups/vectis-YYYYMMDD-HHMMSS.tar.gz --confirm
   ```

8. **Update DNS records to point to new server IP:**
   - A/AAAA records for mail hostname
   - MX records for all domains
   - PTR record (reverse DNS) — contact hosting provider

9. **Verify recovery:**
   ```bash
   vectis health
   vectis status
   # Check deliverability for each domain:
   # Admin UI → Deliverability → Run checks
   ```

**Expected duration:** 45-60 minutes (excluding DNS propagation).

---

### Scenario C: Orchestrator rollback (failed update)

**Symptoms:** Update applied, health checks failing, services degraded.

**Procedure:**

1. **Check orchestrator status:**
   ```bash
   vectis update status
   ```
   If the orchestrator detected the failure, it may have already auto-rolled back.

2. **Manual rollback:**
   ```bash
   vectis update rollback
   ```
   This restores the pre-update database snapshot and reverts container versions.

3. **Verify:**
   ```bash
   vectis health
   vectis update status  # should show "idle"
   ```

**Expected duration:** 5-10 minutes.

---

### Scenario D: Partial data loss (specific domain/mailbox)

**Symptoms:** Missing mailbox data, accidentally deleted domain.

**Procedure:**

1. **Create a current backup first** (to preserve current state):
   ```bash
   vectis backup create
   ```

2. **Restore from a backup that contains the lost data** to a temporary location:
   ```bash
   mkdir /tmp/vectis-restore
   tar -xzf /var/vectis/backups/vectis-YYYYMMDD-HHMMSS.tar.gz -C /tmp/vectis-restore
   ```

3. **Extract specific data:**
   - For mail data: copy specific Maildir from `mail-data.tar`
   - For database records: extract `database.sql` and query for specific rows

4. **Manually restore the specific data** using `psql` or file copy.

5. **Clean up:**
   ```bash
   rm -rf /tmp/vectis-restore
   ```

**Note:** This is a manual process. Full restore is simpler but overwrites all data.

---

## 5. Cross-Region Replication (Future)

For production deployments requiring geographic redundancy:

### Current recommendation (Phase 1.5)
- **Off-site backup copy:** Schedule daily rsync of `/var/vectis/backups/` to a remote server or object storage (S3, B2, etc.)
- **secrets.yaml:** Store in a password manager or encrypted vault accessible from both regions
- **DNS failover:** Use Cloudflare DNS with health checks for automatic failover (requires DNS TTL consideration)

### Future (Phase 3 — Clustering)
- Native multi-node clustering with shared state
- Docker overlay networks for cross-node communication
- Postgres replication for zero-RPO database recovery
- Valkey replication for session continuity

---

## 6. DR Drill Schedule

| Drill | Frequency | Procedure |
|-------|-----------|-----------|
| Backup verification | Weekly (automated) | Verify backup exists and is within RPO |
| Backup restore test | Monthly | Restore to test environment, verify data integrity |
| Full rebuild drill | Quarterly | Simulate Scenario B on a clean test server |
| Orchestrator rollback test | After each update | Verify rollback path works after applying updates |

### Drill checklist
- [ ] Latest backup is within RPO window
- [ ] Backup archive passes integrity check
- [ ] `secrets.yaml` is accessible from secure storage
- [ ] Restore completes without errors
- [ ] All services healthy after restore (`vectis health`)
- [ ] Mail send/receive works after restore
- [ ] Deliverability checks pass for all domains
- [ ] Admin UI accessible and functional
- [ ] Audit log intact

---

## 7. Contact Information

| Role | Contact |
|------|---------|
| System Owner | [Your name / role] |
| Hosting Provider | [Update with provider details] |
| DNS Provider | [e.g. Cloudflare, Route 53] |
| Production Server | [Update after production deployment] |

---

## 8. Key File Paths

| Path | Purpose | Backed up? |
|------|---------|-----------|
| `/etc/vectis/config.yaml` | System configuration | Yes |
| `/etc/vectis/secrets.yaml` | Sensitive credentials | **No** (manual) |
| `/var/vectis/mail/` | Maildir storage | Yes |
| `/var/vectis/dkim/` | DKIM private keys | Yes |
| `/var/vectis/backups/` | Backup archives | Source |
| `/var/vectis/snapshots/` | Pre-update DB snapshots | No (ephemeral) |
| `/var/vectis/certs/` | Mail TLS certificates | No (auto-renewed) |
