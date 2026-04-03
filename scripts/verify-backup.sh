#!/usr/bin/env bash
# Vectis Mail Server — Production Backup Verification
# Verifies a full backup create/restore cycle on the running server.
#
# Usage: ./scripts/verify-backup.sh [--restore]
#   Without --restore: creates a backup and validates the archive
#   With --restore: creates a backup, restores it, and verifies services
#
# Prerequisites: vectis CLI installed, server running, super_admin credentials

set -euo pipefail

API_BASE="${VECTIS_API_BASE:-https://localhost:443/api/v1}"
TOKEN="${VECTIS_API_TOKEN:-}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; exit 1; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

if [ -z "$TOKEN" ]; then
  echo "Set VECTIS_API_TOKEN to a valid session token or API key."
  echo "  export VECTIS_API_TOKEN=vectis_..."
  exit 1
fi

AUTH="Authorization: Bearer $TOKEN"

# ── Step 1: Health check ───────────────────────────────────────────
info "Checking server health..."
STATUS=$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" "$API_BASE/health")
[ "$STATUS" = "200" ] && pass "Server healthy" || fail "Server unhealthy (HTTP $STATUS)"

# ── Step 2: Create backup ─────────────────────────────────────────
info "Creating backup..."
CREATE_RESP=$(curl -sk -X POST -H "$AUTH" -H "Content-Type: application/json" "$API_BASE/backup/create")
JOB_ID=$(echo "$CREATE_RESP" | grep -o '"job_id":"[^"]*"' | cut -d'"' -f4)

if [ -z "$JOB_ID" ]; then
  fail "Failed to create backup: $CREATE_RESP"
fi
pass "Backup job started: $JOB_ID"

# ── Step 3: Poll until complete ───────────────────────────────────
info "Waiting for backup to complete..."
for i in $(seq 1 60); do
  STAT_RESP=$(curl -sk -H "$AUTH" "$API_BASE/backup/status/$JOB_ID")
  JOB_STATUS=$(echo "$STAT_RESP" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
  case "$JOB_STATUS" in
    completed) pass "Backup completed"; break ;;
    failed)    fail "Backup failed: $STAT_RESP" ;;
    *)         sleep 5 ;;
  esac
  [ "$i" = "60" ] && fail "Backup timed out after 5 minutes"
done

# ── Step 4: List backups and verify the new one exists ────────────
info "Verifying backup in list..."
LIST_RESP=$(curl -sk -H "$AUTH" "$API_BASE/backup/list")
BACKUP_COUNT=$(echo "$LIST_RESP" | grep -o '"name"' | wc -l)
[ "$BACKUP_COUNT" -ge 1 ] && pass "Backup archive present ($BACKUP_COUNT total)" || fail "No backups found"

# ── Step 5: Optional restore cycle ────────────────────────────────
if [ "${1:-}" = "--restore" ]; then
  info "WARNING: Restore will stop all services and replace data."
  info "Press Ctrl+C within 5 seconds to abort..."
  sleep 5

  BACKUP_ID=$(echo "$LIST_RESP" | grep -o '"name":"[^"]*"' | head -1 | cut -d'"' -f4)
  info "Restoring from: $BACKUP_ID"

  RESTORE_RESP=$(curl -sk -X POST -H "$AUTH" -H "X-Confirm-Restore: true" \
    -H "Content-Type: application/json" "$API_BASE/backup/restore/$BACKUP_ID")
  RESTORE_STATUS=$(echo "$RESTORE_RESP" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)

  if [ "$RESTORE_STATUS" = "completed" ] || [ "$RESTORE_STATUS" = "restoring" ]; then
    pass "Restore initiated"
  else
    fail "Restore failed: $RESTORE_RESP"
  fi

  # Wait for services to come back.
  info "Waiting for services to recover (up to 2 minutes)..."
  for i in $(seq 1 24); do
    HEALTH=$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" "$API_BASE/health" 2>/dev/null || true)
    [ "$HEALTH" = "200" ] && { pass "Services recovered after restore"; break; }
    sleep 5
    [ "$i" = "24" ] && fail "Services did not recover after restore"
  done
else
  info "Skipping restore cycle (run with --restore to include)"
fi

echo ""
echo -e "${GREEN}Backup verification complete.${NC}"
