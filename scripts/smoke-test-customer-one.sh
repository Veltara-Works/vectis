#!/usr/bin/env bash
# Regression smoke test for the Vectis Mail Customer #1 (in-product) checkout
# flow against the Vx partner-key endpoint.
#
# Run after every release touching:
#   - internal/api/handle_account.go    (handleUpgradeCheckoutSession)
#   - internal/validonx/checkout.go     (CreateCheckoutSession)
#   - internal/config/schema.go         (ValidonXSecrets.CustomerOneKey)
#   - web/src/pages/License.tsx         (Buy Pro button)
# And manually whenever Vx ships a change to /api/v1/integration/checkout/create-session.
#
# Usage:
#   ./scripts/smoke-test-customer-one.sh                  # against prod Vx
#   ./scripts/smoke-test-customer-one.sh --json /tmp/out.json
#   ./scripts/smoke-test-customer-one.sh --verbose
#   VECTIS_CUSTOMER_ONE_KEY=... ./scripts/smoke-test-customer-one.sh   # explicit key
#
# What this script DOES exercise (safe, no money moved):
#   1. partner-key auth: POST with X-API-Key reaches Vx and is accepted
#   2. new-signup branch:  tenant_id omitted → 201 with cs_live_ session
#   3. upgrade-existing branch: tenant_id set → either 201 (session for tenant)
#      or documented 4xx (tenant-not-found). Both prove the branch is reached.
#   4. wire-shape parity: full body with all v0.1.14 fields (product_code,
#      price_id, customer_email, customer_name, success_url, cancel_url,
#      metadata.vectis_install_fingerprint, metadata.source) is accepted.
#
# What this script does NOT exercise:
#   - Through the v0.1.14 admin-side proxy at mail.<host>/api/v1/account/
#     upgrade-checkout-session. That requires an active super_admin session
#     cookie; gated as a manual click-test post-cutover. (Stub at the bottom.)
#   - Full Stripe payment via Playwright. Needs a TEST-mode price; tracked
#     in Vx coordination thread (2026-05-19-checkout-create-session-follow-up-reply-2.md §C).
#   - Webhook receipt + tenant provisioning. Vx-side responsibility.
#
# Idempotency note: a fresh run timestamp is mixed into the install
# fingerprint so each run mints a *new* cs_live_. The actual production
# install fingerprint (machine-id + hostname, what v0.1.14 ships) is
# exercised only at release-cutover time via a manual probe.
#
# Tag convention: all probe emails use probe+customer-one-*@vectismail.com
# so Vx can filter them out of audit dashboards. metadata.source is set
# to "smoke-probe" — first-class allowlisted enum value on the Customer #1
# endpoint (Vx PR #71 merged 2026-05-20T06:53:24Z, asked for in
# /opt/vectis-private-notes/docs/notes/validonx/2026-05-20-customer-one-smoke-results-and-source-ask.md).
# Per-run customer_name carries the "Smoke probe" tag for the secondary
# audit-filter cut. Real production traffic from the in-product Buy Pro
# button uses source:"smoke-probe" — see internal/api/handle_account.go.

set -u

VX_BASE="https://api.validonx.com"
JSON_OUT=""
VERBOSE=0

while [ $# -gt 0 ]; do
  case "$1" in
    --vx-base) VX_BASE="$2"; shift 2 ;;
    --json)    JSON_OUT="$2"; shift 2 ;;
    --verbose) VERBOSE=1; shift ;;
    -h|--help)
      sed -n '2,/^set -u/p' "$0" | sed 's/^# \?//; /^$/d'
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

# ---- partner key ----------------------------------------------------------
# Precedence: env var > secrets.yaml. The yaml fallback only works when the
# user can read /etc/vectis/secrets.yaml (mode 0600, owner johnsmith on prod).
PARTNER_KEY="${VECTIS_CUSTOMER_ONE_KEY:-}"
if [ -z "$PARTNER_KEY" ] && [ -r /etc/vectis/secrets.yaml ]; then
  PARTNER_KEY=$(awk '/^[[:space:]]*customer_one_key:/ { gsub(/"/,"",$2); print $2; exit }' /etc/vectis/secrets.yaml)
fi
if [ -z "$PARTNER_KEY" ]; then
  echo "ERROR: VECTIS_CUSTOMER_ONE_KEY not set and validonx.customer_one_key not readable from /etc/vectis/secrets.yaml" >&2
  exit 2
fi

# ---- install fingerprint (with run-ts mixed in, so each run gets a new session) ----
#
# Per-probe fingerprint variation matters: Vx derives a deterministic
# Stripe Idempotency-Key as `vx-integration-checkout:<product>:<sha256(fingerprint)>`.
# Two probes in the same run sharing one fingerprint but differing on
# metadata (e.g. new-signup vs upgrade-existing — the latter adds
# metadata[customer_one_tenant_id]) collide on the Stripe side and yield
# a 400 "Keys for idempotent requests can only be used with the same
# parameters they were first used with" which Vx wraps as 502
# CHECKOUT.INTEGRATION_STRIPE_ERROR. Mix the probe label into the
# fingerprint so each probe type gets its own idempotency namespace —
# same-probe retries within a run still benefit from idempotency.
# (Root-caused 2026-05-20 by Vx; harness fix is on our side.)
MACHINE_ID=$(cat /etc/machine-id 2>/dev/null || echo "")
HOST_NAME=$(hostname 2>/dev/null || echo "")
RUN_TS=$(date -u +%Y-%m-%dT%H%M%SZ)
BASE_FINGERPRINT=$(printf '%s' "smoke-${RUN_TS}|${MACHINE_ID}|${HOST_NAME}" | sha256sum | awk '{print $1}')

probe_fingerprint() {
  # $1 = probe label ("new-signup", "upgrade", etc.) — namespace the
  # Stripe Idempotency-Key per probe type so calls with different
  # metadata can't collide on the same key. Re-hash to keep the wire
  # value a 64-char sha256 hex (matches the production fingerprint shape).
  printf '%s' "${BASE_FINGERPRINT}|${1}" | sha256sum | awk '{print $1}'
}

# ---- probe metadata ----
PROBE_EMAIL_BASE="probe+customer-one"
SUCCESS_URL="https://mail.vectismail.com/admin/license?checkout=success&session={CHECKOUT_SESSION_ID}"
CANCEL_URL="https://mail.vectismail.com/admin/license?checkout=cancel"
PRODUCT_CODE="vectis-mail"
PRICE_ID="price_1TUlqrBBhyrgaTgwLHyuvLVD"

# Upgrade-existing probe tenant_id: env override > generated-bogus.
#
# When VECTIS_SMOKE_TENANT_ID is set to a real Vx tenant UUID, the upgrade
# probe asserts a full 201 cs_live_ response.
#
# When unset (the default), we send a well-formed but non-existent UUID; the
# expected response is 404 TENANT.NOT_FOUND. That still proves the
# upgrade-existing branch is reached, the tenant lookup happens, and Vx's
# error envelope is correct — only the tenant doesn't exist. This is the
# safest CI-friendly assertion until we have a long-lived test-tenant UUID
# on Vx side (or our own real tenant post-launch).
UPGRADE_TENANT_ID="${VECTIS_SMOKE_TENANT_ID:-}"
EXPECT_UPGRADE_201=1
if [ -z "$UPGRADE_TENANT_ID" ]; then
  UPGRADE_TENANT_ID=$(printf "00000000-0000-0000-0000-%012d" "$(date +%s)")
  EXPECT_UPGRADE_201=0
fi

TMP=$(mktemp); trap 'rm -f "$TMP"' EXIT
fail=0
pass=0
results_json='[]'

log() { [ "$VERBOSE" -eq 1 ] && echo "[smoke] $*" >&2 || true; }

record() {
  local label="$1" status="$2" detail="${3:-}"
  results_json=$(jq --arg l "$label" --arg s "$status" --arg d "$detail" '. + [{label: $l, status: $s, detail: $d}]' <<<"$results_json")
}

# probe_vx <label> <probe-email-suffix> <tenant_id-or-empty> <expect_201>
# POSTs to /api/v1/integration/checkout/create-session with the full v0.1.14
# body shape. tenant_id is omitted when empty (new-signup); otherwise included
# (upgrade-existing). When expect_201=0, a 404 TENANT.NOT_FOUND is also
# accepted as a soft-pass (proves the branch was reached with a bogus UUID).
probe_vx() {
  local label="$1" email_suffix="$2" tenant_id="$3" expect_201="${4:-1}"
  local probe_email="${PROBE_EMAIL_BASE}-${email_suffix}-${RUN_TS}@vectismail.com"
  local fp
  fp=$(probe_fingerprint "$email_suffix")

  # Build body via jq so quoting + omit-tenant-when-empty is reliable.
  local body
  if [ -n "$tenant_id" ]; then
    body=$(jq -n \
      --arg pc "$PRODUCT_CODE" \
      --arg pid "$PRICE_ID" \
      --arg em "$probe_email" \
      --arg nm "Smoke probe ${email_suffix} ${RUN_TS}" \
      --arg tid "$tenant_id" \
      --arg su "$SUCCESS_URL" \
      --arg cu "$CANCEL_URL" \
      --arg fp "$fp" \
      '{product_code:$pc, price_id:$pid, customer_email:$em, customer_name:$nm, tenant_id:$tid, success_url:$su, cancel_url:$cu, metadata:{vectis_install_fingerprint:$fp, source:"smoke-probe"}}')
  else
    body=$(jq -n \
      --arg pc "$PRODUCT_CODE" \
      --arg pid "$PRICE_ID" \
      --arg em "$probe_email" \
      --arg nm "Smoke probe ${email_suffix} ${RUN_TS}" \
      --arg su "$SUCCESS_URL" \
      --arg cu "$CANCEL_URL" \
      --arg fp "$fp" \
      '{product_code:$pc, price_id:$pid, customer_email:$em, customer_name:$nm, success_url:$su, cancel_url:$cu, metadata:{vectis_install_fingerprint:$fp, source:"smoke-probe"}}')
  fi

  log "POST ${VX_BASE}/api/v1/integration/checkout/create-session (probe=${email_suffix})"
  log "body: ${body}"

  local status
  status=$(curl -sS -o "$TMP" -w "%{http_code}" -X POST "${VX_BASE}/api/v1/integration/checkout/create-session" \
    -H "Content-Type: application/json" \
    -H "Accept: application/json" \
    -H "X-API-Key: ${PARTNER_KEY}" \
    --data-binary "$body")

  log "status=${status} body=$(cat "$TMP")"

  if [ "$status" = "201" ]; then
    local session_id checkout_url request_id
    session_id=$(jq -r '.data.session_id // ""' < "$TMP")
    checkout_url=$(jq -r '.data.checkout_url // ""' < "$TMP")
    request_id=$(jq -r '.meta.request_id // ""' < "$TMP")
    if [[ "$session_id" == cs_live_* ]] && [[ "$checkout_url" == https://checkout.stripe.com/* ]]; then
      echo "✓ $label — session ${session_id} req ${request_id}"
      pass=$((pass + 1))
      record "$label" "pass" "status=201 session=${session_id} request_id=${request_id}"
      return 0
    else
      echo "✗ $label — status=201 but session_id/checkout_url malformed (session='${session_id}' url='${checkout_url}')"
      fail=$((fail + 1))
      record "$label" "fail" "status=201 malformed session=${session_id}"
      return 1
    fi
  fi

  # Non-201: extract Vx error envelope if present. request_id is captured
  # for fail/soft-pass too so we can quote it back to Vx when a probe fails
  # — Vx looks up the same id in its server-side request log.
  local err_code err_msg request_id
  err_code=$(jq -r '.error.code // .code // ""' < "$TMP" 2>/dev/null)
  err_msg=$(jq -r '.error.message // .message // ""' < "$TMP" 2>/dev/null)
  request_id=$(jq -r '.meta.request_id // .error.details.context.requestId // ""' < "$TMP" 2>/dev/null)

  # Soft-pass: when expect_201=0 (upgrade-existing probe with a bogus tenant_id)
  # a 404 TENANT.NOT_FOUND is the expected outcome — it proves the branch was
  # reached and the tenant lookup happened.
  if [ "$expect_201" = "0" ] && [ "$status" = "404" ] && [ "$err_code" = "TENANT.NOT_FOUND" ]; then
    echo "✓ $label — soft-pass (404 TENANT.NOT_FOUND for bogus tenant_id; branch reached) req ${request_id}"
    pass=$((pass + 1))
    record "$label" "pass" "soft-pass status=404 code=TENANT.NOT_FOUND request_id=${request_id} (bogus tenant_id, branch reached)"
    return 0
  fi

  echo "✗ $label — status=${status} code='${err_code}' message='${err_msg}' req ${request_id}"
  fail=$((fail + 1))
  record "$label" "fail" "status=${status} code=${err_code} request_id=${request_id} message=${err_msg}"
  return 1
}

# probe_vx_auth_negative: confirms a known-bad key is rejected. Cheap
# safety net so an accidental key leak in env/secrets doesn't sail through.
probe_vx_auth_negative() {
  local label="auth negative — bogus X-API-Key rejected"
  local status
  status=$(curl -sS -o "$TMP" -w "%{http_code}" -X POST "${VX_BASE}/api/v1/integration/checkout/create-session" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: vectis_thiskeydoesnotexist_smoke" \
    --data-binary "{\"product_code\":\"${PRODUCT_CODE}\",\"price_id\":\"${PRICE_ID}\"}")
  if [ "$status" = "401" ] || [ "$status" = "403" ]; then
    echo "✓ $label — status ${status}"
    pass=$((pass + 1))
    record "$label" "pass" "status=${status}"
  else
    echo "✗ $label — expected 401/403, got ${status}"
    fail=$((fail + 1))
    record "$label" "fail" "status=${status}"
  fi
}

echo "Smoke test: Vectis Mail Customer #1 checkout @ ${VX_BASE}"
echo "Run timestamp: ${RUN_TS}"
echo "Install fingerprint (smoke-prefixed, base): ${BASE_FINGERPRINT:0:16}..."
echo ""

probe_vx_auth_negative
probe_vx "new-signup branch (tenant_id omitted)"  "new-signup" ""                    1
probe_vx "upgrade-existing branch (tenant_id set)" "upgrade"    "$UPGRADE_TENANT_ID" "$EXPECT_UPGRADE_201"

echo ""
echo "Results: ${pass} pass, ${fail} fail"
echo ""
echo "Note: each pass created a cs_live_ session that will expire unpaid in"
echo "24h. Vx audit filter: api_key_id=<customer-one-v2> AND email LIKE"
echo "'probe+customer-one-%'. Cumulative artefacts this run: ${pass} (if all passed)."

# ---------------------------------------------------------------------------
# Stub: through-the-proxy test, enabled after v0.1.14 prod cutover.
# Requires an active super_admin session cookie at mail.<host>; cookie
# provisioning is left to the operator (login via the web UI + copy the
# vectis_session cookie into an env var). Until then, this is a manual step.
# ---------------------------------------------------------------------------
#
# probe_through_proxy() {
#   local mail_host="${1:-https://mail.vectismail.com}"
#   local session_cookie="${VECTIS_SESSION_COOKIE:-}"
#   if [ -z "$session_cookie" ]; then
#     echo "- skipping through-proxy test (VECTIS_SESSION_COOKIE not set)"
#     return 0
#   fi
#   local status
#   status=$(curl -sS -o "$TMP" -w "%{http_code}" -X POST \
#     "${mail_host}/api/v1/account/upgrade-checkout-session" \
#     -H "Content-Type: application/json" \
#     -H "Cookie: vectis_session=${session_cookie}" \
#     --data-binary '{}')
#   # ... assertion on 200 + url starts with https://checkout.stripe.com/
# }

if [ -n "$JSON_OUT" ]; then
  jq -n \
    --arg vx_base "$VX_BASE" \
    --arg ts "$RUN_TS" \
    --arg fp "$BASE_FINGERPRINT" \
    --argjson pass "$pass" \
    --argjson fail "$fail" \
    --argjson results "$results_json" \
    '{vx_base: $vx_base, run_ts: $ts, base_fingerprint: $fp, pass: $pass, fail: $fail, results: $results}' \
    > "$JSON_OUT"
  echo "JSON report: $JSON_OUT"
fi

exit "$fail"
