#!/bin/bash
# STOPGAP — scheduled backups for prod until v0.1.18 ships the in-app
# backup.Scheduler (internal/backup/scheduler.go). The in-app scheduler honours
# config.yaml backup.{enabled,schedule,retain_days}; this host cron does the same
# job with the v0.1.17 image that has no scheduler.
#
# REMOVE at the v0.1.18 cutover (after setting backup.enabled: true), to avoid
# double backups:
#   sudo rm -f /etc/cron.d/vectis-backup /usr/local/bin/vectis-backup-cron.sh
#
# Creates a backup via the api container (writes to the host-mounted
# /var/vectis/backups — see DR finding F1) and prunes archives older than
# RETAIN_DAYS, always keeping the most recent.
set -euo pipefail

RETAIN_DAYS=30
BACKUP_DIR=/var/vectis/backups
LOG=/var/log/vectis-backup-cron.log

ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

{
  echo "$(ts) scheduled backup starting"
  if docker exec vectis-api vectis backup create; then
    echo "$(ts) backup create OK"
  else
    echo "$(ts) ERROR backup create failed"
    exit 1
  fi

  # Retention: remove vectis-*.tar.gz[.enc] older than RETAIN_DAYS, but never the
  # newest (there must always be at least one restorable backup). The manual
  # pre-*.sql.gz cutover dumps are left untouched. mapfile avoids a pipeline so
  # an empty match never trips pipefail.
  newest="$(ls -t "$BACKUP_DIR"/vectis-*.tar.gz* 2>/dev/null | head -1 || true)"
  mapfile -t old < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'vectis-*.tar.gz*' -mtime +"$RETAIN_DAYS")
  for f in "${old[@]}"; do
    [ -z "$f" ] && continue
    [ "$f" = "$newest" ] && continue
    echo "$(ts) pruning $f"
    rm -f "$f"
  done
  echo "$(ts) done"
} >> "$LOG" 2>&1
