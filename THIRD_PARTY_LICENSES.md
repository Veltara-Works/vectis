# Third-Party Licenses

Vectis Mail itself is distributed under the Business Source License 1.1 (see
[`LICENSE`](LICENSE)). This document lists the third-party software that Vectis
Mail incorporates or distributes, together with the license each component is
made available under.

It covers three categories:

1. **Go modules** compiled into the Vectis binaries (`vectis`, `orchestrator`,
   `render-configs`).
2. **npm packages** bundled into the shipped admin UI.
3. **Container images** referenced by the deployment templates.

All directly-compiled and bundled dependencies (categories 1 and 2) are under
permissive licenses (MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0) — there is **no copyleft and
no unknown/unlicensed code linked into the Vectis binaries or the admin UI
bundle**. The copyleft components in the stack (Roundcube, the optional Grafana
observability profile, acme.sh) are independent upstream programs run in their
own containers at arm's length; see the [Container images](#3-container-images)
section for the analysis.

> **How this file is generated.** Categories 1 and 2 are produced by tooling, not
> by hand — see [Regenerating this file](#regenerating-this-file). Category 3 is
> maintained manually and each entry was verified against the upstream license
> file. Last generated **2026-05-29** (Go 1.25.10, `go-licenses` v1.6.0);
> incrementally updated **2026-06-08** for the Enterprise SAML SSO dependencies
> (`crewjam/saml` + its compiled transitives), each license re-verified with
> `go-licenses` v1.6.0. Build toolchain bumped to **Go 1.26.4** on **2026-06-12**
> (`golang:1.26-alpine` builders); the module graph is unchanged, so the section-1
> license inventory below remains valid as last generated.

---

## 1. Go modules (compiled into the binaries)

These are the third-party Go modules actually imported and compiled into the
shipped binaries, as reported by `go-licenses` over `./...` (test-only and
unused graph dependencies are excluded). A few modules vendor a second component
under its own license file (e.g. `go-jose/json`, the Prometheus internal `gddo`
fork) and are listed separately to reflect that.

**Summary:** 38 entries — 12 MIT, 11 BSD-3-Clause, 13 Apache-2.0, 2 BSD-2-Clause.

| Module / package | Version | License |
|---|---|---|
| `github.com/beevik/etree` | v1.6.0 | BSD-2-Clause |
| `github.com/beorn7/perks/quantile` | v1.0.1 | MIT |
| `github.com/boombuler/barcode` | 6c824513bacc | MIT |
| `github.com/cespare/xxhash/v2` | v2.3.0 | MIT |
| `github.com/coreos/go-oidc/v3/oidc` | v3.18.0 | Apache-2.0 |
| `github.com/crewjam/saml` | v0.5.1 | BSD-2-Clause |
| `github.com/go-chi/chi/v5` | v5.3.0 | MIT |
| `github.com/go-jose/go-jose/v4` | v4.1.4 | Apache-2.0 |
| `github.com/go-jose/go-jose/v4/json` | v4.1.4 | BSD-3-Clause |
| `github.com/golang-jwt/jwt/v4` | v4.5.2 | MIT |
| `github.com/golang-migrate/migrate/v4` | v4.19.1 | MIT |
| `github.com/google/uuid` | v1.6.0 | BSD-3-Clause |
| `github.com/jackc/pgerrcode` | 469b46aa5efa | MIT |
| `github.com/jackc/pgpassfile` | v1.0.0 | MIT |
| `github.com/jackc/pgservicefile` | 5a60cdf6a761 | MIT |
| `github.com/jackc/pgx/v5` | v5.10.0 | MIT |
| `github.com/jackc/puddle/v2` | v2.2.2 | MIT |
| `github.com/jonboulle/clockwork` | v0.5.0 | Apache-2.0 |
| `github.com/mattermost/xml-roundtrip-validator` | v0.1.0 | Apache-2.0 |
| `github.com/munnerz/goautoneg` | a7dc8b61c822 | BSD-3-Clause |
| `github.com/pquerna/otp` | v1.5.0 | Apache-2.0 |
| `github.com/prometheus/client_golang/internal/.../gddo/httputil` | v1.23.2 | BSD-3-Clause |
| `github.com/prometheus/client_golang/prometheus` | v1.23.2 | Apache-2.0 |
| `github.com/prometheus/client_model/go` | v0.6.2 | Apache-2.0 |
| `github.com/prometheus/common` | v0.66.1 | Apache-2.0 |
| `github.com/prometheus/procfs` | v0.16.1 | Apache-2.0 |
| `github.com/russellhaering/goxmldsig` | v1.6.0 | Apache-2.0 |
| `github.com/spf13/cobra` | v1.10.2 | Apache-2.0 |
| `github.com/spf13/pflag` | v1.0.6 | BSD-3-Clause |
| `github.com/valkey-io/valkey-go` | v1.0.75 | Apache-2.0 |
| `go.yaml.in/yaml/v2` | v2.4.2 | Apache-2.0 |
| `golang.org/x/crypto` | v0.53.0 | BSD-3-Clause |
| `golang.org/x/oauth2` | v0.30.0 | BSD-3-Clause |
| `golang.org/x/sync/semaphore` | v0.20.0 | BSD-3-Clause |
| `golang.org/x/sys` | v0.46.0 | BSD-3-Clause |
| `golang.org/x/text` | v0.35.0 | BSD-3-Clause |
| `google.golang.org/protobuf` | v1.36.8 | BSD-3-Clause |
| `gopkg.in/yaml.v3` | v3.0.1 | MIT |

The Go standard library is part of the Go distribution itself and is licensed
under BSD-3-Clause; it is not enumerated above.

---

## 2. npm packages (bundled into the admin UI)

The admin UI (`web/`) is built with Vite and the compiled bundle is served as
static assets. Only the **runtime** dependencies end up in the shipped bundle;
the build-time `devDependencies` (Vite, TypeScript, ESLint, etc.) are not
distributed and are out of scope.

**Summary:** 7 runtime packages — all MIT.

| Package | Version | License |
|---|---|---|
| `react` | 19.2.4 | MIT |
| `react-dom` | 19.2.4 | MIT |
| `scheduler` | 0.27.0 | MIT |
| `react-router-dom` | 7.13.2 | MIT |
| `react-router` | 7.13.2 | MIT |
| `cookie` | 1.1.1 | MIT |
| `set-cookie-parser` | 2.7.2 | MIT |

---

## 3. Container images

The deployment templates pull a number of third-party container images. These
are **independent works** distributed by their upstream maintainers under their
own licenses. Vectis Mail invokes them at arm's length — each runs as a separate
process in its own container and communicates over network/IPC boundaries — so
the copyleft obligations of the GPL/AGPL components below apply to **those
upstream programs only** and do **not** extend to Vectis Mail's own code (mere
aggregation). Where Vectis builds a derived image, it does so without modifying
the upstream copyleft program's source.

| Image | License | Role | Notes |
|---|---|---|---|
| `alpine:3.21` | MIT (Alpine), **GPL-2.0-only** (BusyBox), MIT (musl libc) | Runtime base for most Vectis images | We redistribute derived images; BusyBox/musl sources are provided by Alpine upstream. |
| `nginx:alpine` | BSD-2-Clause | Static asset server (admin UI) | |
| `roundcube/roundcubemail:1.7.1-apache` | **GPL-3.0-or-later** | Webmail | Used unmodified; only skin/config supplied. Roundcube's plugin/skin exception explicitly excludes such add-ons from copyleft. |
| `traefik:v3.3` | MIT | Reverse proxy / TLS | |
| `postgres:17-alpine` | PostgreSQL License (permissive, BSD-style) | Database | |
| `valkey/valkey:8-alpine` | BSD-3-Clause | Cache / key-value store | |
| `golang:1.26-alpine` | BSD-3-Clause (Go) | **Build-time only** (multi-stage builder) | Discarded; not shipped in final images. |
| `node:24` / `node:24-alpine` | MIT (Node.js) | **Build-time only** (admin UI builder) | Discarded; not shipped in final images. |

### Optional profiles (not in the default `small` runtime profile)

These images are referenced only by opt-in deployment profiles and are **not**
part of the default production stack:

| Image | License | Profile |
|---|---|---|
| `grafana/grafana:11.5` | **AGPL-3.0-only** | observability |
| `grafana/loki:3.4` | **AGPL-3.0-only** | observability |
| `grafana/promtail:3.4` | **AGPL-3.0-only** | observability |
| `edoburu/pgbouncer:1.23.1-p2` | ISC (PgBouncer) | connection pooling |
| `neilpang/acme.sh` | **GPL-3.0** | alternate ACME cert path (default deployments use the built-in cert-extractor instead) |

The AGPL-3.0 Grafana components, where deployed, run as standalone services. The
AGPL's network-source-availability obligation is satisfied by the unmodified
upstream images (Grafana Labs publishes the corresponding source); Vectis ships
no modifications to them.

---

## License compatibility summary

- **Linked/bundled code (categories 1 & 2):** 100% permissive
  (MIT / BSD-2 / BSD-3 / Apache-2.0 / PostgreSQL). No copyleft is linked into the
  Vectis binaries or the admin UI bundle. Compatible with redistribution under
  the Business Source License 1.1.
- **Container images (category 3):** permissive except for Roundcube
  (GPL-3.0-or-later), acme.sh (GPL-3.0), and the optional Grafana stack
  (AGPL-3.0-only). All are arm's-length separate programs used unmodified; no
  derivative-work or source-disclosure obligation falls on Vectis Mail's code.

---

## Regenerating this file

Sections 1 and 2 are tool-generated. Section 3 (container images) is maintained
by hand — update it when a base image or pulled image changes in a `Dockerfile`
or a compose template.

**Go modules (section 1):**

```sh
# go-licenses v1.6.0 needs a real SDK GOROOT (not the toolchain-cache GOROOT
# that GOTOOLCHAIN=auto produces), or it fails to resolve the standard library.
go install github.com/google/go-licenses@latest
go install golang.org/dl/go1.26.4@latest && go1.26.4 download   # -> ~/sdk/go1.26.4

GOROOT="$HOME/sdk/go1.26.4" PATH="$HOME/sdk/go1.26.4/bin:$(go env GOPATH)/bin:$PATH" \
  GOTOOLCHAIN=local \
  go-licenses csv ./... --ignore github.com/Veltara-Works/vectis
```

**npm runtime packages (section 2):**

```sh
cd web && npm ls --omit=dev --all
# license field per package: node -e "console.log(require('./node_modules/<pkg>/package.json').license)"
```
