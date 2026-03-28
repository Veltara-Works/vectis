# F. Error Catalogue

**Status:** DRAFT — For review with Copilot before integration into Spec v1.1  
**Prepared by:** Claude (round 5)  
**Complements:** Vectis Architecture v1.3, Implementation Spec v1.0

---

## F.1 Overview

This section catalogues critical failure modes across Vectis operations. For each failure, it defines: how it's detected, what automated recovery occurs (if any), and the manual recovery path.

This is not exhaustive — it covers the critical-path failures that must be handled correctly from Phase 0.5 onward. The error catalogue should be expanded as new failure modes are discovered during implementation and testing.

### Severity levels

| Level | Meaning | Example |
|-------|---------|---------|
| INFO | Non-critical; operation continues | ClamAV signature update minor warning |
| WARN | Degraded but functional; admin should investigate | Disk usage above 80% |
| ERROR | Operation failed; automated recovery attempted | Health check timeout after update |
| CRITICAL | Automated recovery failed; manual intervention required | Rollback failure |

---

## F.2 Installation Failures

| Failure | Detection | Severity | Automated Recovery | Manual Recovery |
|---------|-----------|----------|-------------------|-----------------|
| OS version unsupported | Preflight check (lsb_release) | ERROR | Abort with clear message | Install on supported OS (Ubuntu 24.04 LTS) |
| Insufficient RAM (<2 GB) | Preflight check (free -m) | ERROR | Abort with recommendation | Upgrade server or use `none` ClamAV profile |
| Insufficient disk (<20 GB free) | Preflight check (df) | ERROR | Abort with recommendation | Free disk space or expand volume |
| Docker install fails | apt returns non-zero | ERROR | Abort with error details | Install Docker manually per Docker docs, re-run `vectis install` |
| Port conflict (25, 80, 443, etc.) | Preflight port scan (ss/lsof) | ERROR | Abort; identify conflicting process by name and PID | Stop conflicting service, re-run |
| Outbound port 25 blocked | Preflight SMTP test (connect to known SMTP server) | WARN | Warn but allow install to continue | Contact hosting provider to unblock port 25 |
| DNS A record mismatch | Preflight DNS lookup vs. detected IP | WARN | Warn but allow install | Fix DNS records, or proceed if DNS is being configured |
| Image pull fails (network) | Docker pull returns non-zero | ERROR | Retry 3 times with exponential backoff; abort if all fail | Check DNS resolution, check firewall, retry |
| DB migration fails on first run | Migration runner error | ERROR | Abort; remove containers and volumes; print cleanup command | Check migration logs, fix issue, re-run |
| Health check timeout after install | Container health != healthy after 120s | ERROR | Print per-service status and suggest `vectis logs <service>` | Check logs for the failing service; common causes: port conflict, config error, resource exhaustion |
| Secrets generation fails | Filesystem error or /dev/urandom unavailable | ERROR | Abort | Check filesystem permissions on /etc/vectis/; ensure /dev/urandom is available |

---

## F.3 Update Failures

| Failure | Detection | Severity | Automated Recovery | Manual Recovery |
|---------|-----------|----------|-------------------|-----------------|
| Image pull network failure | Docker pull error (timeout, DNS, auth) | ERROR | Abort plan; no state changed | Fix network, check registry auth, re-run `vectis update plan` |
| Registry authentication failure | HTTP 401/403 from registry | ERROR | Abort; no state changed | Verify license key (Pro images), check GHCR access |
| DB migration SQL error | Migration runner returns error | ERROR | Restore from pg_dump snapshot; revert containers to previous versions | Manual: `psql -U postgres vectis < /var/vectis/snapshots/<file>` |
| Health check timeout post-update | Docker health != healthy after per-service timeout | ERROR | Full automatic rollback (DB snapshot restore + container revert) | If auto-rollback succeeds, check logs. If not, `vectis update rollback` |
| Rollback: DB restore fails | pg_restore / psql returns error | CRITICAL | None — cannot auto-recover | Manual: `psql -U postgres -f /var/vectis/snapshots/<file>`, then `docker compose up -d` with previous image tags. See docs/recovery.md |
| Rollback: old image unavailable | Docker pull error for previous image tag | CRITICAL | None — cannot auto-recover | Manually locate or rebuild old image; or restore from full backup |
| Disk full during update | Write error during migration, image pull, or snapshot | ERROR | Abort; attempt partial cleanup of downloaded images | Free disk space; `vectis update rollback` or `vectis backup restore` |
| Plan staleness detected | Config hash or container versions changed between plan and apply | ERROR | Reject apply; require new plan | Run `vectis update plan` again |
| Orchestrator crash during apply | Advisory lock released; state = running in DB | ERROR | On restart: detect orphaned state, set to failed | Admin runs `vectis update rollback` or `vectis backup restore` |

---

## F.4 Runtime / Operational Failures

| Failure | Detection | Severity | Automated Recovery | Manual Recovery |
|---------|-----------|----------|-------------------|-----------------|
| Postfix stops accepting mail | Docker HEALTHCHECK (TCP connect port 25) | ERROR | Alert (email to admin, webhook) | `vectis logs postfix` → diagnose → `docker compose restart postfix` |
| Dovecot IMAP unavailable | Docker HEALTHCHECK (TCP connect port 993) | ERROR | Alert | `vectis logs dovecot` → diagnose → restart |
| Rspamd unresponsive | Docker HEALTHCHECK (HTTP /ping) | ERROR | Alert; mail still flows but without spam filtering | `vectis logs rspamd` → restart; check memory/CPU limits |
| ClamAV signature update failure | ClamAV log shows freshclam error | WARN | Retry on next update cycle; alert after 3 consecutive failures | Manual: `docker compose exec clamav freshclam`; check network |
| Postgres connection pool exhausted | API returns HTTP 503; pgxpool reports no available connections | ERROR | Alert; API queues requests briefly (up to 5s) | Check for connection leaks in logs; increase pool size in config.yaml; restart API |
| Valkey OOM | Docker HEALTHCHECK (PING fails) | ERROR | Alert; services degrade (no sessions = admins logged out, no queue = background tasks halt) | Flush cache DB: `docker compose exec valkey valkey-cli -n 0 FLUSHDB`; restart Valkey; increase memory limit |
| Disk full (mail storage) | Dovecot rejects delivery; periodic df check by health monitor | ERROR | Alert immediately with disk usage details | Archive old mail; expand disk; add quota limits; `vectis mailbox update --quota` |
| Disk full (Postgres) | Postgres stops accepting writes | CRITICAL | Alert immediately | Free disk space; Postgres may need WAL cleanup; restart if needed |
| TLS certificate renewal failure | Traefik logs show ACME renewal error | WARN | Traefik retries automatically; alert after 3 failures (certificates expire in <7 days) | Check DNS is pointing correctly; check Traefik logs; manual certbot if needed |
| Rspamd high CPU (sustained) | Container CPU usage >90% for >5 minutes | WARN | Alert | Check for misconfigured rules; increase resource limits; consider disabling neural module |
| Mail queue growing | Postfix queue size exceeds threshold | WARN | Alert | `vectis logs postfix`; check for delivery issues; `docker compose exec postfix postqueue -p` |

---

## F.5 Config Apply Failures

| Failure | Detection | Severity | Automated Recovery | Manual Recovery |
|---------|-----------|----------|-------------------|-----------------|
| config.yaml syntax error | YAML parse error with line number | ERROR | Reject apply; no changes made | Fix config.yaml at indicated line |
| config.yaml schema violation | JSON Schema validation failure | ERROR | Reject apply; show specific error and valid values | Fix the invalid setting |
| config.yaml semantic error | Validation engine (e.g., invalid domain format, port out of range) | ERROR | Reject apply; show specific error | Fix the invalid setting |
| secrets.yaml missing | File not found | ERROR | Reject apply | Ensure secrets.yaml exists at /etc/vectis/secrets.yaml with correct permissions (0600) |
| secrets.yaml missing required key | Merge step finds required key absent | ERROR | Reject apply; list missing keys | Add missing keys to secrets.yaml |
| Postfix reload fails after config change | `postfix reload` returns non-zero | ERROR | Revert Postfix config to previous version; retry reload with old config | Check Postfix logs; fix config; re-apply |
| Dovecot reload fails | `doveadm reload` returns non-zero | ERROR | Revert Dovecot config; retry reload with old config | Check Dovecot logs; fix config; re-apply |
| Rspamd reload fails | Rspamd reload signal fails or health check fails post-reload | ERROR | Revert Rspamd config; retry reload with old config | Check Rspamd logs |
| Config drift detected | Generated configs differ from what's currently deployed | WARN | Warn admin with diff; offer auto-correct (overwrite with generated version) | Review diff; decide whether to accept generated version or investigate why drift occurred |
| File lock contention | Another process holds lock on config.yaml | ERROR | Retry 3 times with 1s delay; fail if still locked | Check what process holds the lock; kill if stale |

---

## F.6 Backup & Restore Failures

| Failure | Detection | Severity | Automated Recovery | Manual Recovery |
|---------|-----------|----------|-------------------|-----------------|
| Backup: disk full during pg_dump | pg_dump write error | ERROR | Clean up partial dump file; alert | Free disk space; retry `vectis backup create` |
| Backup: Maildir rsync error | rsync non-zero exit | ERROR | Alert; mark backup as incomplete | Check disk/permissions; retry. Partial backups are retained but marked incomplete |
| Backup: permission denied on DKIM keys | Read error on /var/vectis/dkim/ | ERROR | Skip DKIM keys; mark backup as partial; warn admin | Fix permissions: `chown -R vectis:vectis /var/vectis/dkim/` |
| Restore: corrupt backup archive | tar extraction error (checksum, truncated) | ERROR | Abort restore; no changes made (validation before action) | Obtain a different backup; verify archive integrity with `tar -tzf` |
| Restore: backup version incompatible | Version metadata in backup doesn't match current schema version | ERROR | Abort restore with version mismatch details | May need to install matching Vectis version first, restore, then upgrade |
| Restore: DB restore fails | psql / pg_restore returns error | ERROR | Abort; attempt to restart with existing (pre-restore) data | Manual: `psql -U postgres vectis < dump.sql`; check Postgres logs |
| Restore: services fail health check after restore | Docker HEALTHCHECK fails for one or more services | ERROR | Alert; print failing service logs | Check logs per service; re-restore if data corruption suspected |
| Restore: mail data path mismatch | Backup has different mail path structure than current install | WARN | Attempt automatic path mapping | Manual file move; update config if paths changed between versions |

---

## F.7 Alert Configuration

Alerts are sent via the mechanisms configured in config.yaml:

```yaml
alerts:
  email:
    enabled: true
    recipients:
      - admin@example.com
    # Uses the local Postfix to send (no external SMTP needed)
  webhook:
    enabled: false
    url: https://hooks.slack.com/services/...
    # POST with JSON payload
```

### Alert payload (webhook)

```json
{
  "severity": "ERROR",
  "service": "postfix",
  "message": "Postfix health check failed: TCP connection to port 25 timed out",
  "timestamp": "2026-03-28T12:00:00Z",
  "hostname": "mail.example.com",
  "action_taken": "Alert sent. No automated recovery for runtime failures.",
  "suggested_action": "Check logs: vectis logs postfix"
}
```

### Alert deduplication

- Same alert is not sent more than once per 15 minutes (configurable)
- Alert cleared when the condition resolves (sends a recovery notification)
- CRITICAL alerts bypass deduplication — always sent immediately
