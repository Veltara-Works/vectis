#!/usr/bin/env bash
# Liveness smoke test for the Vectis Mail KEYLESS "Buy Pro" checkout flow.
#
# Probes the live keyless Customer #2 endpoint that the in-product Buy Pro
# button drives through:
#
#   POST {VX_BASE}/api/v1/checkout/vectis-pro
#
# This replaces the retired scripts/smoke-test-customer-one.sh, which exercised
# the removed *keyed* Customer #1 path (X-API-Key partner-key checkout). That
# path no longer exists in production, so the old script returned HTTP 401 on
# every run — an expected false alarm that risked triggering needless rollbacks
# post-cutover. No API key is involved here: the keyless endpoint is anonymous
# and Vx rate-limits per source IP.
#
# Healthy signal:
#   HTTP 422 — the endpoint is alive and reachable. An empty/minimal POST trips
#   Vx's (Laravel) validation for the required owner_email / owner_name fields,
#   which proves the route is registered, served, and keyless WITHOUT minting a
#   real Stripe session or moving any money. This is a pure liveness probe.
#
# Failure signals (real, actionable):
#   401 — endpoint demands a credential (regression: keyed path resurfaced)
#   404 — route missing / renamed / not deployed
#   5xx — upstream error
#   connection failure / timeout — Vx unreachable from this host
#
# What this script intentionally does NOT do:
#   - Mint a real cs_* Stripe session (would require valid owner_* fields).
#   - Test the admin-side proxy at mail.<host>/api/v1/account/
#     upgrade-checkout-session (needs a super_admin session cookie; manual
#     click-test post-cutover).
#   - Drive a full Stripe payment (Playwright, TEST-mode price).
#
# Usage:
#   ./scripts/smoke-test-buy-pro.sh                 # against prod Vx
#   ./scripts/smoke-test-buy-pro.sh --vx-base https://validonx.com
#   ./scripts/smoke-test-buy-pro.sh --json /tmp/out.json
#   ./scripts/smoke-test-buy-pro.sh --verbose
#   ./scripts/smoke-test-buy-pro.sh --dry-run      # print the curl, fire nothing

set -euo pipefail

VX_BASE="https://api.validonx.com"
JSON_OUT=""
VERBOSE=0
DRY_RUN=0
HEALTHY_STATUS="422"
ENDPOINT_PATH="/api/v1/checkout/vectis-pro"

while [ $# -gt 0 ]; do
  case "$1" in
    --vx-base) VX_BASE="$2"; shift 2 ;;
    --json)    JSON_OUT="$2"; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -h|--help)
      sed -n '2,/^set -euo pipefail/p' "$0" | sed 's/^# \?//; /^set -euo/d'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

VX_BASE="${VX_BASE%/}"
URL="${VX_BASE}${ENDPOINT_PATH}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }
log()  { [ "$VERBOSE" -eq 1 ] && echo "[smoke] $*" >&2 || true; }

RUN_TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

echo "Smoke test: Vectis Mail keyless Buy Pro checkout"
echo "Endpoint:   POST ${URL}"
echo "Healthy:    HTTP ${HEALTHY_STATUS} (validation reached → endpoint alive, keyless)"
echo "Run:        ${RUN_TS}"
echo ""

# Minimal keyless POST: empty JSON body, NO X-API-Key. A healthy endpoint
# validates the missing required fields and returns 422 without minting a
# session. We deliberately send nothing that could mint a real checkout.
if [ "$DRY_RUN" -eq 1 ]; then
  info "dry-run — would execute:"
  echo "  curl -sS -o <body> -w '%{http_code}' -X POST '${URL}' \\"
  echo "    -H 'Content-Type: application/json' -H 'Accept: application/json' \\"
  echo "    --data-binary '{}'"
  exit 0
fi

TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT

log "POST ${URL} (empty body, no credential)"

# Capture curl's own exit status separately so a connection failure (DNS,
# refused, timeout) is reported as a distinct FAIL rather than masquerading
# as an empty HTTP code.
set +e
status=$(curl -sS -o "$TMP" -w '%{http_code}' -X POST "$URL" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  --data-binary '{}' \
  --max-time 20 2>"$TMP.err")
curl_rc=$?
set -e

body="$(cat "$TMP" 2>/dev/null || true)"
log "curl_rc=${curl_rc} status=${status} body=${body}"

result_status="fail"
exit_code=1

if [ "$curl_rc" -ne 0 ]; then
  fail "Vx unreachable — curl exit ${curl_rc}: $(cat "$TMP.err" 2>/dev/null)"
  result_status="fail"
  exit_code=1
elif [ "$status" = "$HEALTHY_STATUS" ]; then
  pass "endpoint alive & keyless — HTTP ${status} (validation reached, no credential required)"
  result_status="pass"
  exit_code=0
elif [ "$status" = "401" ] || [ "$status" = "403" ]; then
  fail "endpoint demands a credential — HTTP ${status} (keyed path regression?). body: ${body}"
elif [ "$status" = "404" ]; then
  fail "endpoint missing — HTTP 404 (route renamed / not deployed?). body: ${body}"
elif [ "$status" -ge 500 ] 2>/dev/null; then
  fail "upstream error — HTTP ${status}. body: ${body}"
else
  fail "unexpected status — HTTP ${status} (expected ${HEALTHY_STATUS}). body: ${body}"
fi

rm -f "$TMP.err" 2>/dev/null || true

echo ""
if [ "$result_status" = "pass" ]; then
  echo "Result: 1 pass, 0 fail"
else
  echo "Result: 0 pass, 1 fail"
fi

if [ -n "$JSON_OUT" ]; then
  printf '{"vx_base":"%s","endpoint":"%s","run_ts":"%s","http_status":"%s","curl_rc":%d,"result":"%s"}\n' \
    "$VX_BASE" "$ENDPOINT_PATH" "$RUN_TS" "$status" "$curl_rc" "$result_status" > "$JSON_OUT"
  echo "JSON report: $JSON_OUT"
fi

exit "$exit_code"
