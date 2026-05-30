#!/usr/bin/env bash
# Vectis Mail Server — Docker image garbage collection
#
# Cutovers pull a fresh set of 8 service images each release; old tags are
# never reclaimed and accumulate until they fill the root fs (this happened
# during the v0.1.17 cutover — see docs and the disk-incident memory). This
# routine prunes the backlog so disk never creeps toward a release again.
#
# Two stages, because images alone are only half the story:
#
#   1. Stale apply-helpers. The orchestrator spawns ephemeral
#      'vectis-apply-helper-*' containers during Apply; once exited they
#      serve no purpose but each one pins the orchestrator image of its
#      release. Left behind, they are the real reason the backlog never
#      clears — a plain image prune can't touch a pinned image. This stage
#      removes the EXITED ones (running stacks are never touched).
#
#   2. Images. For each ghcr.io/veltara-works/vectis-* repository, KEEP:
#        - any image used by a container that survives stage 1
#        - the ':latest' tag
#        - the newest N stable version tags (default 2; --keep N to change)
#      Everything else (older stables, every rc/beta not in use) is removed,
#      then dangling (untagged) layers are pruned.
#
# Usage:
#   ./scripts/prune-images.sh            # DRY-RUN: print what would be removed
#   ./scripts/prune-images.sh --apply    # actually remove
#   ./scripts/prune-images.sh --keep 3   # keep newest 3 stable per repo
#   ./scripts/prune-images.sh --apply --keep 3
#
# Safe by default: dry-run unless --apply; only EXITED helpers are removed
# (never a running container); never uses 'rmi -f', so Docker refuses to
# delete any image a surviving container still references.

set -euo pipefail

REPO_PREFIX="ghcr.io/veltara-works/vectis-"
KEEP=2
APPLY=0

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
keep_msg()  { echo -e "${GREEN}[KEEP]${NC}   $1"; }
drop_msg()  { echo -e "${RED}[REMOVE]${NC} $1"; }
info()      { echo -e "${YELLOW}[INFO]${NC}   $1"; }

while [ $# -gt 0 ]; do
  case "$1" in
    --apply)    APPLY=1 ;;
    --keep)     shift; KEEP="${1:?--keep needs a number}" ;;
    --keep=*)   KEEP="${1#--keep=}" ;;
    -h|--help)  grep '^#' "$0" | sed 's/^#\s\?//'; exit 0 ;;
    *) echo "unknown arg: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

command -v docker >/dev/null 2>&1 || { echo "docker not found on PATH" >&2; exit 1; }
case "$KEEP" in ''|*[!0-9]*) echo "--keep must be a non-negative integer" >&2; exit 2 ;; esac

# ── Stage 1: stale apply-helper containers (exited only) ───────────
mapfile -t STALE_HELPERS < <(
  docker ps -a --filter 'name=vectis-apply-helper-' --filter 'status=exited' \
    --format '{{.ID}} {{.Names}} ({{.Status}})'
)
if [ "${#STALE_HELPERS[@]}" -gt 0 ]; then
  info "${#STALE_HELPERS[@]} exited apply-helper container(s) to remove:"
  for h in "${STALE_HELPERS[@]}"; do drop_msg "container ${h#* }"; done
  echo ""
fi
# IDs only, for removal + exclusion from the in-use set below.
STALE_IDS_FILE="$(mktemp)"
printf '%s\n' "${STALE_HELPERS[@]}" | awk 'NF{print $1}' > "$STALE_IDS_FILE"

# ── In-use image IDs ───────────────────────────────────────────────
# '.Image' is the full sha256 ID, matched against 'docker images --no-trunc'
# IDs below. Containers slated for removal in stage 1 are EXCLUDED, so the
# dry-run reflects the post-cleanup state (otherwise dead helpers would pin
# old images and nothing would ever be reclaimable).
INUSE_FILE="$(mktemp)"
trap 'rm -f "$INUSE_FILE" "$STALE_IDS_FILE"' EXIT
docker ps -aq | grep -vxF -f "$STALE_IDS_FILE" 2>/dev/null \
  | xargs -r docker inspect -f '{{.Image}}' | sort -u > "$INUSE_FILE" || true

mapfile -t REPOS < <(docker images "${REPO_PREFIX}*" --format '{{.Repository}}' | sort -u)
if [ "${#REPOS[@]}" -eq 0 ]; then
  info "No ${REPO_PREFIX}* images present — nothing to do."
  exit 0
fi

REMOVE=()
for repo in "${REPOS[@]}"; do
  # Newest N stable tags (exclude rc/beta), version-sorted descending.
  mapfile -t keep_stable < <(
    docker images "$repo" --format '{{.Tag}}' \
      | grep -E '^v[0-9]' | grep -vE -- '-(rc|beta)' | sort -Vr | head -n "$KEEP"
  )

  while IFS=$'\t' read -r tag id; do
    [ "$tag" = "<none>" ] && continue
    ref="$repo:$tag"
    if [ "$tag" = "latest" ]; then
      keep_msg "$ref  (latest)"; continue
    fi
    if grep -qxF "$id" "$INUSE_FILE"; then
      keep_msg "$ref  (in use by a container)"; continue
    fi
    is_recent=0
    for k in "${keep_stable[@]:-}"; do [ "$k" = "$tag" ] && { is_recent=1; break; }; done
    if [ "$is_recent" = 1 ]; then
      keep_msg "$ref  (recent stable)"; continue
    fi
    drop_msg "$ref"
    REMOVE+=("$ref")
  done < <(docker images "$repo" --no-trunc --format '{{.Tag}}\t{{.ID}}')
done

echo ""
NUM_HELPERS="$(awk 'NF' "$STALE_IDS_FILE" | wc -l)"
if [ "${#REMOVE[@]}" -eq 0 ] && [ "$NUM_HELPERS" -eq 0 ]; then
  info "Nothing to remove. Backlog is clean."
  if [ "$APPLY" = 1 ]; then docker image prune -f >/dev/null && info "Pruned dangling layers."; fi
  exit 0
fi

info "Selected: ${NUM_HELPERS} stale helper container(s), ${#REMOVE[@]} image tag(s) (keep=$KEEP newest stable per repo)."

if [ "$APPLY" != 1 ]; then
  echo ""
  info "DRY-RUN — nothing removed. Re-run with --apply to execute."
  exit 0
fi

AVAIL_BEFORE="$(df -h --output=avail / | tail -1 | tr -d ' ')"

# Stage 1: remove exited apply-helpers first so their pinned images become
# reclaimable in stage 2.
if [ "$NUM_HELPERS" -gt 0 ]; then
  xargs -r docker rm < "$STALE_IDS_FILE" >/dev/null && info "Removed ${NUM_HELPERS} stale helper container(s)."
fi

# Stage 2: image tags, then dangling layers.
for ref in "${REMOVE[@]}"; do
  docker rmi "$ref" >/dev/null || info "could not remove $ref (still referenced?) — skipped"
done
docker image prune -f >/dev/null && info "Pruned dangling layers."

AVAIL_AFTER="$(df -h --output=avail / | tail -1 | tr -d ' ')"
echo ""
info "Root fs available: ${AVAIL_BEFORE} -> ${AVAIL_AFTER}"
echo -e "${GREEN}Image GC complete.${NC}"
