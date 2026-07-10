#!/usr/bin/env bash
#
# pre-push-audit.sh — in-house adversarial gate, run BEFORE you commit/push.
#
# Purpose: land code in CI and PR review already checked, so there are very few
# comebacks. It mirrors the hard CI gates (ci.yml, dependency-security.yml),
# adds a working-tree secret scan and extra static analysis, and prints a
# PASS / WARN / FAIL summary. Exit is non-zero on any hard failure, so it can be
# wired as a git pre-push hook:
#
#   ln -sf ../../scripts/pre-push-audit.sh .git/hooks/pre-push
#
# ─── SAFETY: never run the Go toolchain on a production mail host ────────────
# A full Go build/test has OOM-killed and rebooted a live server before. So the
# Go compile / vet / test / vuln / license gates are OFF BY DEFAULT. They run
# only when you export:
#
#   export VECTIS_BUILD_HOST=1     # in your build box / dev shell profile ONLY
#
# Never set that on a server running the live mail stack. As an extra belt, the
# Go gates refuse to run if a live vectis mail stack (postfix/dovecot container)
# is detected on the local Docker daemon. On any host without the flag, the Go
# gates are skipped and left to CI, while the fast gates (format, gitignore,
# TLS policy, secrets) and the frontend gates still run locally.
#
# Usage:
#   scripts/pre-push-audit.sh [--no-frontend] [--full] [--strict] [-h|--help]
#     --no-frontend  skip the web/ TypeScript type-check, test and build gates
#     --full         also run the integration/docker/backup suites — build host
#                    only; needs postgres/valkey/docker + pg17 client available
#     --strict       treat advisory gates (staticcheck) as hard failures
#
# Env:
#   VECTIS_BUILD_HOST=1        enable the Go toolchain gates (build host only)
#   VECTIS_GO_TEST_TAGS=...    extra build tags for the unit test run (rare)
#
set -uo pipefail

# ── repo root ───────────────────────────────────────────────────────────────
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

# ── args ──────────────────────────────────────────────────────────────────--
RUN_FRONTEND=1 ; RUN_FULL=0 ; STRICT=0
for a in "$@"; do
  case "$a" in
    --no-frontend) RUN_FRONTEND=0 ;;
    --full)        RUN_FULL=1 ;;
    --strict)      STRICT=1 ;;
    -h|--help)     sed -n '2,40p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $a (try --help)" >&2; exit 2 ;;
  esac
done

# ── pretty output + result tracking ───────────────────────────────────────--
if [ -t 1 ]; then B=$'\e[1m'; R=$'\e[31m'; G=$'\e[32m'; Y=$'\e[33m'; D=$'\e[2m'; Z=$'\e[0m'
else B=""; R=""; G=""; Y=""; D=""; Z=""; fi
FAILS=0 ; WARNS=0 ; declare -a SUMMARY
hr(){ printf '%s\n' "────────────────────────────────────────────────────────"; }
skip(){ SUMMARY+=("  ${D}SKIP${Z}  $1${2:+  ${D}($2)${Z}}"); }
pass(){ SUMMARY+=("  ${G}PASS${Z}  $1"); }
warn(){ SUMMARY+=("  ${Y}WARN${Z}  $1"); WARNS=$((WARNS+1)); }
fail(){ SUMMARY+=("  ${R}FAIL${Z}  $1"); FAILS=$((FAILS+1)); }

# gate NAME [--advisory] -- CMD...   (advisory failures WARN unless --strict)
gate(){
  local name="$1"; shift
  local advisory=0
  if [ "${1:-}" = "--advisory" ]; then advisory=1; shift; fi
  [ "$1" = "--" ] && shift
  printf '%s▶ %s%s\n' "$B" "$name" "$Z"
  local out rc
  out="$("$@" 2>&1)"; rc=$?
  if [ $rc -eq 0 ]; then
    pass "$name"
  else
    printf '%s\n' "$out" | sed 's/^/    /'
    if [ $advisory -eq 1 ] && [ $STRICT -eq 0 ]; then warn "$name (advisory)"; else fail "$name"; fi
  fi
}

echo "${B}Vectis pre-push audit${Z}  ${D}(root: $ROOT)${Z}"
hr

# ════════════════════════════════════════════════════════════════════════════
# FAST GATES — safe on any host (no compiler invoked)
# ════════════════════════════════════════════════════════════════════════════

# 1) .gitignore source-file guard (mirrors ci.yml ignored-source-check)
gitignore_guard(){
  # Mirrors ci.yml's allowlist, plus local-only tool-scratch dirs that never
  # exist in CI's clean checkout (.playwright-mcp, .agents, .mcp, .cache) so the
  # guard doesn't false-flag them when run from a working dev tree.
  local allowed='^(web/node_modules/|web/dist/|web/build/|\.venv/|__pycache__/|var/|full_auto_provisioner_setup/|coverage/|target/|vendor/|\.claude/|\.idea/|\.vscode/|\.playwright-mcp/|\.agents/|\.mcp/|\.cache/)'
  local exts='\.(go|ts|tsx|js|jsx|py|rs|sh|sql|yml|yaml|md|html|css|scss|toml|proto|rb|java|kt|swift|c|cc|cpp|h|hpp)$'
  local off; off="$(git ls-files --others --ignored --exclude-standard | grep -E "$exts" | grep -vE "$allowed" || true)"
  [ -z "$off" ] || { echo "Source files hidden by .gitignore:"; echo "$off"; return 1; }
}
gate "gitignore source guard" -- gitignore_guard

# 2) TLS policy: no OpenSSL-family deps in the module graph (mirrors ci.yml)
tls_policy(){
  if grep -iEn 'openssl|boring|native-tls' go.mod go.sum 2>/dev/null; then
    echo "OpenSSL-family dep found; first-party code must use Go stdlib crypto/tls only."
    return 1
  fi
}
gate "TLS policy (go.mod/go.sum)" -- tls_policy

# 3) gofmt — formatting (gofmt only parses/formats, never compiles → safe)
gofmt_check(){
  # gofmt -l lists files needing formatting on stdout; a parse error goes to
  # stderr AND makes gofmt exit non-zero. Split file-listing from the gofmt run
  # and check the exit status so a broken file FAILs the gate instead of a
  # suppressed error silently passing it.
  local files bad rc
  files="$(git ls-files '*.go' | grep -vE '(^|/)(vendor|web/node_modules)/' || true)"
  [ -n "$files" ] || return 0
  bad="$(printf '%s\n' "$files" | xargs -r gofmt -l 2>&1)"; rc=$?
  if [ $rc -ne 0 ]; then echo "gofmt failed to run (parse error?):"; echo "$bad"; return 1; fi
  [ -z "$bad" ] || { echo "gofmt needs to run on:"; echo "$bad"; echo "fix: gofmt -w <files>"; return 1; }
}
if command -v gofmt >/dev/null 2>&1; then gate "gofmt" -- gofmt_check
else skip "gofmt" "gofmt not found"; fi

# 4) secret scan — DIFF-SCOPED (fast; never walks web/node_modules):
#    (a) uncommitted changes you're about to commit, and
#    (b) commits staged for push but not yet on origin/main.
secret_scan(){
  local cfg=(); [ -f .gitleaks.toml ] && cfg=(--config .gitleaks.toml)
  local rc=0
  gitleaks protect "${cfg[@]}" --redact --no-banner || rc=$?
  if git rev-parse --verify --quiet origin/main >/dev/null; then
    gitleaks detect "${cfg[@]}" --redact --no-banner --log-opts="origin/main..HEAD" || rc=$?
  fi
  return $rc
}
if command -v gitleaks >/dev/null 2>&1; then gate "gitleaks secret scan" -- secret_scan
else skip "gitleaks secret scan" "gitleaks not installed"; fi

# ════════════════════════════════════════════════════════════════════════════
# FRONTEND GATES — web/ admin UI (moderate memory; run unless --no-frontend)
# ════════════════════════════════════════════════════════════════════════════
if [ $RUN_FRONTEND -eq 1 ] && [ -d web ]; then
  if command -v npm >/dev/null 2>&1; then
    ( cd web && [ -d node_modules ] || npm ci ) >/dev/null 2>&1 || true
    gate "web: tsc --noEmit"  -- bash -c 'cd web && npx --no-install tsc --noEmit'
    gate "web: unit tests"    -- bash -c 'cd web && npm test --silent'
    gate "web: build"         -- bash -c 'cd web && npm run build --silent'
  else
    skip "frontend gates" "npm not found"
  fi
else
  skip "frontend gates" "$([ $RUN_FRONTEND -eq 0 ] && echo '--no-frontend' || echo 'no web/ dir')"
fi

# ════════════════════════════════════════════════════════════════════════════
# GO TOOLCHAIN GATES — build host ONLY (compile/test/vuln); OOM-safe by default
# ════════════════════════════════════════════════════════════════════════════
go_gates_enabled(){
  [ "${VECTIS_BUILD_HOST:-0}" = "1" ] || return 1
  # Belt: refuse if a live vectis mail stack is running on the local daemon.
  if command -v docker >/dev/null 2>&1 \
     && docker ps --format '{{.Names}}' 2>/dev/null | grep -qE '^vectis-(postfix|dovecot)$'; then
    echo "REFUSING Go build: a live vectis mail stack is running here — this looks" >&2
    echo "like a production host. Run the Go gates on a dedicated build box or CI." >&2
    return 1
  fi
  return 0
}

# lazily install a pinned Go tool into a temp GOBIN (build host only).
# Guard mktemp failure: an empty GOBIN_TMP would make PATH ":$PATH" (a leading
# empty element = CWD on PATH) and make `go install` fall back to the user's
# default GOBIN, polluting the host. On failure we leave GOBIN_TMP empty and
# need_tool skips installs (tools must already be present).
GOBIN_TMP="$(mktemp -d 2>/dev/null || true)"
if [ -n "$GOBIN_TMP" ] && [ -d "$GOBIN_TMP" ]; then
  export PATH="$GOBIN_TMP:$PATH"
else
  GOBIN_TMP=""
fi
need_tool(){ # need_tool <bin> <install-path@version>
  command -v "$1" >/dev/null 2>&1 && return 0
  [ -n "$GOBIN_TMP" ] || return 1   # no temp GOBIN → don't install into host GOBIN
  echo "  ${D}installing $1...${Z}"
  GOBIN="$GOBIN_TMP" go install "$2" >/dev/null 2>&1
}

if go_gates_enabled; then
  if ! command -v go >/dev/null 2>&1; then
    fail "Go toolchain gates (go not found despite VECTIS_BUILD_HOST=1)"
  else
    gate "go vet ./..."            -- go vet ./...
    gate "go build (CGO-free)"     -- bash -c 'CGO_ENABLED=0 go build -tags netgo,osusergo -ldflags="-s -w" -o /tmp/vectis-prepush ./cmd/vectis/ && /tmp/vectis-prepush version >/dev/null'
    # Build the go-test argv as an array so VECTIS_GO_TEST_TAGS is passed as a
    # single, literal argument — no shell re-parsing of spaces/metacharacters.
    gotest=(go test ./internal/... -count=1)
    [ -n "${VECTIS_GO_TEST_TAGS:-}" ] && gotest=(go test -tags "$VECTIS_GO_TEST_TAGS" ./internal/... -count=1)
    gate "go unit tests"           -- "${gotest[@]}"

    need_tool govulncheck golang.org/x/vuln/cmd/govulncheck@v1.3.0
    if command -v govulncheck >/dev/null 2>&1; then gate "govulncheck ./..." -- govulncheck ./...
    else warn "govulncheck (install failed)"; fi

    need_tool go-licenses github.com/google/go-licenses@v1.6.0
    if command -v go-licenses >/dev/null 2>&1; then
      gate "go-licenses (no forbidden/restricted)" -- go-licenses check ./... --disallowed_types=forbidden,restricted --ignore github.com/Veltara-Works/vectis
    else warn "go-licenses (install failed)"; fi

    # Adversarial static analysis beyond `go vet` (advisory unless --strict)
    need_tool staticcheck honnef.co/go/tools/cmd/staticcheck@2025.1.1
    if command -v staticcheck >/dev/null 2>&1; then gate "staticcheck ./..." --advisory -- staticcheck ./...
    else warn "staticcheck (install failed)"; fi

    if [ $RUN_FULL -eq 1 ]; then
      gate "integration tests" -- bash -c "go test -tags integration \$(go list -tags integration ./internal/... | grep -v '/internal/backup') -p 1 -count=1 -timeout 300s"
    else
      skip "integration/docker/backup suites" "add --full on a host with pg/valkey/docker"
    fi
  fi
else
  skip "Go toolchain gates (vet/build/test/vuln/licenses/staticcheck)" \
       "$([ "${VECTIS_BUILD_HOST:-0}" = "1" ] && echo 'refused: live mail stack detected' || echo 'set VECTIS_BUILD_HOST=1 on a build host')"
fi
[ -n "$GOBIN_TMP" ] && rm -rf "$GOBIN_TMP" 2>/dev/null || true

# ════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ════════════════════════════════════════════════════════════════════════════
hr; echo "${B}Summary${Z}"
for line in "${SUMMARY[@]}"; do printf '%s\n' "$line"; done
hr
if [ $FAILS -gt 0 ]; then
  echo "${R}${B}✖ $FAILS gate(s) failed — do NOT push.${Z} ${D}($WARNS warning(s))${Z}"
  exit 1
fi
if [ "${VECTIS_BUILD_HOST:-0}" != "1" ]; then
  echo "${Y}⚠ Fast gates passed, but the Go toolchain gates were NOT run here.${Z}"
  echo "${D}  Verify Go on a build host (VECTIS_BUILD_HOST=1) or rely on CI before merge.${Z}"
fi
echo "${G}${B}✓ All run gates passed.${Z} ${D}($WARNS warning(s))${Z}"
exit 0
