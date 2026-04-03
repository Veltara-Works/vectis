#!/usr/bin/env bash
# Vectis Mail Server — Production Orchestrator Verification
# Verifies the update orchestrator plan/apply/rollback cycle.
#
# Usage: ./scripts/verify-orchestrator.sh [--apply]
#   Without --apply: runs plan only (safe, no changes)
#   With --apply: runs plan → apply → verify health
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

# ── Step 2: Check orchestrator status ─────────────────────────────
info "Checking orchestrator status..."
ORCH_RESP=$(curl -sk -H "$AUTH" "$API_BASE/orchestrator/status")
ORCH_STATE=$(echo "$ORCH_RESP" | grep -o '"state":"[^"]*"' | cut -d'"' -f4)
pass "Orchestrator state: $ORCH_STATE"

if [ "$ORCH_STATE" != "idle" ] && [ "$ORCH_STATE" != "completed" ]; then
  fail "Orchestrator is not idle (state: $ORCH_STATE). Wait for current operation to complete."
fi

# ── Step 3: Plan ──────────────────────────────────────────────────
info "Running orchestrator plan..."
PLAN_RESP=$(curl -sk -X POST -H "$AUTH" -H "Content-Type: application/json" "$API_BASE/orchestrator/plan")
PLAN_ERR=$(echo "$PLAN_RESP" | grep -o '"error"' || true)

if [ -n "$PLAN_ERR" ]; then
  ERROR_MSG=$(echo "$PLAN_RESP" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
  fail "Plan failed: $ERROR_MSG"
fi
pass "Plan completed successfully"

# ── Step 4: Check history ─────────────────────────────────────────
info "Checking orchestrator history..."
HIST_RESP=$(curl -sk -H "$AUTH" "$API_BASE/orchestrator/history")
HIST_COUNT=$(echo "$HIST_RESP" | grep -o '"id"' | wc -l)
pass "History contains $HIST_COUNT operations"

# ── Step 5: Optional apply cycle ──────────────────────────────────
if [ "${1:-}" = "--apply" ]; then
  info "Running orchestrator apply..."
  APPLY_RESP=$(curl -sk -X POST -H "$AUTH" -H "Content-Type: application/json" "$API_BASE/orchestrator/apply")
  APPLY_ERR=$(echo "$APPLY_RESP" | grep -o '"error"' || true)

  if [ -n "$APPLY_ERR" ]; then
    ERROR_MSG=$(echo "$APPLY_RESP" | grep -o '"message":"[^"]*"' | cut -d'"' -f4)
    fail "Apply failed: $ERROR_MSG"
  fi
  pass "Apply initiated"

  # Wait for apply to complete and services to stabilize.
  info "Waiting for apply to complete (up to 5 minutes)..."
  for i in $(seq 1 60); do
    STAT=$(curl -sk -H "$AUTH" "$API_BASE/orchestrator/status")
    STATE=$(echo "$STAT" | grep -o '"state":"[^"]*"' | cut -d'"' -f4)
    case "$STATE" in
      idle|completed) pass "Apply completed (state: $STATE)"; break ;;
      failed)         fail "Apply failed. Check orchestrator history for details." ;;
      *)              sleep 5 ;;
    esac
    [ "$i" = "60" ] && fail "Apply timed out after 5 minutes"
  done

  # Final health check.
  info "Running post-apply health check..."
  sleep 5
  HEALTH=$(curl -sk -o /dev/null -w '%{http_code}' -H "$AUTH" "$API_BASE/health")
  [ "$HEALTH" = "200" ] && pass "Post-apply health check passed" || fail "Post-apply health check failed (HTTP $HEALTH)"
else
  info "Skipping apply cycle (run with --apply to include)"
fi

echo ""
echo -e "${GREEN}Orchestrator verification complete.${NC}"
