#!/usr/bin/env bash
# Vectis Mail Server — govulncheck gate
#
# Wraps `govulncheck` so an advisory whose vulnerable code we call can be
# explicitly and TEMPORARILY accepted when no fixed version exists and it is not
# exploitable here, without turning the scan off (which would hide every future
# finding too). Same rules as scripts/npm-audit-gate.sh.
#
# Every acceptance lives in .govulncheck-allow.json with a reason and an expiry.
# Only "called" findings count (the vulnerable symbol is reachable from our
# code), which is exactly what plain `govulncheck ./...` fails on. The gate
# fails if:
#   1. a called finding is not in the allowlist              -> new finding
#   2. an allowlist entry is past its `expires` date         -> must be revisited
#   3. an allowlist entry matches no called finding          -> stale, delete it
#
# (3) is how a fix gets noticed: once the dependency is bumped past the advisory,
# the entry goes stale and the gate asks for it to be removed.
#
# Usage: ./scripts/govulncheck-gate.sh   (govulncheck and jq on PATH)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ALLOW_FILE="$REPO_ROOT/.govulncheck-allow.json"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; }
info() { echo -e "${YELLOW}[INFO]${NC} $1"; }

command -v jq >/dev/null || { fail "jq is required but not installed."; exit 1; }
command -v govulncheck >/dev/null || { fail "govulncheck is required but not installed."; exit 1; }

TODAY="$(date -u +%Y-%m-%d)"

# Human-readable report first, for the CI log. Its exit status is ignored: the
# decision below is made from the JSON stream.
(cd "$REPO_ROOT" && govulncheck ./...) || true

# -format json exits 0 when it finds vulnerabilities and non-zero only when the
# scan itself fails, so a failure here is a real error (stderr shows why).
SCAN_JSON="$(cd "$REPO_ROOT" && govulncheck -format json ./...)" \
  || { fail "govulncheck -format json failed — see its stderr above."; exit 1; }

# OSV IDs of called findings: the first trace frame names a function in our
# dependency, which only happens when the vulnerable symbol is reachable.
FOUND="$(jq -rs '
  [ .[] | select(has("finding")) | .finding
    | select((.trace // [])[0].function // "" | length > 0)
    | .osv ] | unique | .[]' <<<"$SCAN_JSON")"

if [ -f "$ALLOW_FILE" ]; then
  jq -e '.advisories | type == "array"' "$ALLOW_FILE" >/dev/null 2>&1 \
    || { fail "$ALLOW_FILE is malformed (expected an .advisories array)."; exit 1; }
  ALLOWED="$(jq -r '.advisories[].id' "$ALLOW_FILE")"
else
  ALLOWED=""
fi

STATUS=0

# 1. Anything called that we have not explicitly accepted.
while IFS= read -r id; do
  [ -n "$id" ] || continue
  if ! grep -qxF "$id" <<<"$ALLOWED"; then
    detail="$(jq -rs --arg id "$id" '[ .[] | select(has("osv")) | .osv | select(.id == $id) | .summary ] | first // ""' <<<"$SCAN_JSON")"
    fail "Unaccepted $id — $detail"
    STATUS=1
  fi
done <<<"$FOUND"

# 2 & 3. Validate each acceptance against today's scan.
while IFS= read -r id; do
  [ -n "$id" ] || continue
  expires="$(jq -r --arg id "$id" '.advisories[] | select(.id == $id) | .expires' "$ALLOW_FILE")"

  if ! grep -qxF "$id" <<<"$FOUND"; then
    fail "Stale acceptance $id — no longer reported as called. Remove it from $(basename "$ALLOW_FILE")."
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
  pass "govulncheck: no unaccepted called vulnerabilities ($n accepted advisor$([ "$n" = 1 ] && echo y || echo ies))."
fi

exit "$STATUS"
