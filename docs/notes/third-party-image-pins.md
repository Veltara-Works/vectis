# Third-party base-image digest pins

The third-party base images in the generated stack are pinned by digest
(`tag@sha256:…`) in `internal/engine/templates/docker-compose.yml.tmpl`, plus
`alpine:3.24` for the DKIM-migration container in
`internal/orchestrator/docker.go` (`dkimMigrationImage`).

## Why

A bare tag (`postgres:17-alpine`) is mutable: the upstream publisher — or an
attacker with registry push access — can move it to different bytes, and every
`docker compose pull` silently runs whatever the tag now points at. Digest-pinning
makes docker verify the content-addressed digest on pull, so the bytes we run are
exactly the bytes we vetted. This is the third-party half of REL-3 (the
2026-07-06 prelaunch-delta audit); the Vectis-* images are pinned separately via
the Ed25519-signed release manifest.

## Maintenance — MANUAL

Dependabot's `docker` ecosystem scans Dockerfiles and literal `docker-compose.yml`
files. It **cannot** parse `docker-compose.yml.tmpl` (the Go `{{ }}` template
syntax is not valid YAML), so these digests are **not** auto-bumped. Bump them by
hand when moving to a new base-image version:

1. Choose the new tag (or keep the tag, refresh the digest for a security patch).
2. Resolve the current manifest-list digest for the tag (run in a shell — this
   is a plain command, this file is not rendered through Go's template engine):

   ```
   docker buildx imagetools inspect <image>:<tag> --format '{{.Manifest.Digest}}'
   ```

3. Update the `image:` line to `image: <image>:<tag>@<digest>`.
4. Bump both the tag and the digest together; never leave a tag/digest mismatch.
5. Check the upstream release notes for post-upgrade steps (e.g. PostgreSQL
   minor releases sometimes ask for a `REINDEX` of certain index types).

## Existing installs do NOT pick up a new third-party pin by themselves

`vectis update apply` renders the new compose (so the new pin lands in the
file), but Phase 4.3 only recreates the `vectis-*` image services
(`VectisImageServicesExcludingSelf()`). Postgres, Valkey, pgbouncer, Traefik and
the observability stack keep running the old image until something recreates
them. Until the update pipeline handles this (planned for v0.1.66), a pin bump
reaches existing installs only through a manual
`docker compose -f /etc/vectis/docker-compose.yml up -d --no-deps <service>`
after the update, plus any post-upgrade step the release notes require.

Nothing tracks these pins automatically: Dependabot can't parse the template and
Trivy only scans the 8 images we build. Check them against upstream at least
monthly, and whenever upstream announces a security release, until that is
automated.

## Pinning policy

- Images **deployed in production** are pinned to the digest currently running in
  prod (known-good, validated) — a pure pin with no behaviour change.
- Optional images not deployed in prod (grafana/loki/promtail, pgbouncer) are
  pinned to the current registry digest at pin time.

## Current pins (2026-07-06; postgres, valkey and alpine refreshed 2026-11-22)

| Image | Tag | Digest | Source |
|-------|-----|--------|--------|
| traefik | v3.3 | `sha256:2cd5cc75…43d09f` | prod-running |
| postgres | 17-alpine | `sha256:f9cf3e1f…d07d73` | registry, 2026-11-22: PostgreSQL 17.12 (was 17.9) |
| valkey/valkey | 8-alpine | `sha256:9971099a…cfc3fc` | registry, 2026-11-22: Valkey 8.1.12 (was 8.1.6) |
| alpine (dkim) | 3.24 | `sha256:f59abe65…48c71bf` | registry, 2026-11-22 |
| grafana/loki | 3.4 | `sha256:5fe9fa99…b5aac2` | registry |
| grafana/promtail | 3.4 | `sha256:168eb785…c5ff050` | registry |
| grafana/grafana | 11.5 | `sha256:4d1b2146…8fd3259` | registry |
| edoburu/pgbouncer | v1.23.1-p2 | `sha256:122bac47…cfcd49` | registry |

Note: `edoburu/pgbouncer` was corrected from the (now-removed) unprefixed
`1.23.1-p2` tag to the current `v1.23.1-p2` scheme while pinning — the old ref no
longer resolved on Docker Hub.
