#!/usr/bin/env bash
# Vectis Mail Server — npm audit gate (admin UI)
#
# Wraps `npm audit` so a high/critical advisory can be explicitly and TEMPORARILY
# accepted when it is provably not exploitable here — without lowering the
# --audit-level threshold, which would blind us to every future finding too.
#
# Every acceptance lives in web/.npm-audit-allow.json with a reason and an expiry.
# The gate fails if:
#   1. a high/critical advisory is not in the allowlist       -> new finding
#   2. an allowlist entry is past its `expires` date          -> must be revisited
#   3. an allowlist entry matches no live advisory            -> stale, delete it
#
# (3) matters: a lingering fixed entry would silently re-suppress the same
# advisory if a later dependency bump reintroduced it.
#
# Usage: ./scripts/npm-audit-gate.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WEB_DIR="$REPO_ROOT/web"
ALLOW_FILE="$WEB_DIR/.npm-audit-allow.json"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

command -v jq >/dev/null || { fail "jq is required but not installed."; exit 1; }

TODAY="$(date -u +%Y-%m-%d)"

# npm audit exits non-zero whenever it finds anything, so capture rather than
# let `set -e` abort. A malformed report is itself a failure.
#
# Only stdout is captured, so npm's stderr is deliberately left to flow to the
# console: a registry outage, proxy or auth error is the most likely reason this
# step ever breaks, and swallowing it would leave nothing to debug from.
AUDIT_JSON="$(cd "$WEB_DIR" && npm audit --json || true)"
if ! jq -e 'has("vulnerabilities")' <<<"$AUDIT_JSON" >/dev/null 2>&1; then
  fail "npm audit did not return a parseable report — see its stderr above."
  echo "--- raw stdout (first 40 lines) ---" >&2
  head -n 40 <<<"$AUDIT_JSON" >&2
  exit 1
fi

# Advisory IDs actually found, at high/critical only. Transitive entries list
# their parent package as a plain string in `via`; only object entries carry a
# real advisory, so those string entries correctly contribute nothing here.
FOUND="$(jq -r '
  [ .vulnerabilities[].via[]
    | select(type == "object")
    | select(.severity == "high" or .severity == "critical")
    | (.url | split("/") | last)
  ] | unique | .[]' <<<"$AUDIT_JSON")"

if [ -f "$ALLOW_FILE" ]; then
  jq -e '.advisories | type == "array"' "$ALLOW_FILE" >/dev/null 2>&1 \
    || { fail "$ALLOW_FILE is malformed (expected an .advisories array)."; exit 1; }
  ALLOWED="$(jq -r '.advisories[].id' "$ALLOW_FILE")"
else
  ALLOWED=""
fi

STATUS=0

# 1. Anything found that we have not explicitly accepted.
while IFS= read -r id; do
  [ -n "$id" ] || continue
  if ! grep -qxF "$id" <<<"$ALLOWED"; then
    detail="$(jq -r --arg id "$id" '
      [ .vulnerabilities[].via[]
        | select(type == "object")
        | select((.url | split("/") | last) == $id)
        | "\(.name): \(.title)"
      ] | first // $id' <<<"$AUDIT_JSON")"
    fail "Unaccepted $id — $detail"
    STATUS=1
  fi
done <<<"$FOUND"

# 2 & 3. Validate each acceptance against today's report.
while IFS= read -r id; do
  [ -n "$id" ] || continue
  expires="$(jq -r --arg id "$id" \
    '.advisories[] | select(.id == $id) | .expires' "$ALLOW_FILE")"

  if ! grep -qxF "$id" <<<"$FOUND"; then
    fail "Stale acceptance $id — no longer reported. Remove it from $(basename "$ALLOW_FILE")."
    STATUS=1
  elif [[ ! "$expires" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]]; then
    fail "Acceptance $id has a missing or malformed \`expires\` date."
    STATUS=1
  elif [[ "$TODAY" > "$expires" ]]; then
    fail "Acceptance $id EXPIRED on $expires — re-assess and patch or re-date it."
    STATUS=1
  else
    info "Accepted $id until $expires"
  fi
done <<<"$ALLOWED"

if [ "$STATUS" -eq 0 ]; then
  n="$(grep -c . <<<"$ALLOWED" || true)"
  pass "npm audit clean at high+ ($n accepted advisor$([ "$n" = 1 ] && echo y || echo ies))."
fi

exit "$STATUS"
