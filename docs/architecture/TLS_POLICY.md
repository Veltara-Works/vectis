# Vectis Mail — TLS Policy

**Status:** Ratified 2026-04-17
**Applies to:** Vectis Mail (this repository)
**Part of:** shared TLS policy

## Statement

> **Use memory-safe TLS implementations where we control the choice.
> Don't add new greenfield OpenSSL surface. Keep upstream OSS services
> (Postfix, Dovecot, Rspamd, Traefik, Roundcube) on their standard
> crypto — it's been audited for decades — and keep the distro
> packages current.**

This policy was ratified across the our repositories on 2026-04-17.
a sibling service (Rust) satisfies it via `rustls`. Vectis Mail (Go + upstream C
services) satisfies it as described below.

## Scope

### First-party code — policy-compliant

All Go code in this repository (the `vectis` API/CLI binary and the
`orchestrator` binary) uses **Go stdlib `crypto/tls`** exclusively.
`crypto/tls` is pure Go, memory-safe, and has no OpenSSL linkage. It is
the Go-ecosystem equivalent of `rustls`.

**Enforcement:**

1. **No CGO.** Both binaries build with `CGO_ENABLED=0` and the
   `netgo,osusergo` build tags, forcing the pure-Go DNS resolver and
   user/group lookup paths. This is baked into
   [docker/api/Dockerfile](../../docker/api/Dockerfile) and
   [docker/orchestrator/Dockerfile](../../docker/orchestrator/Dockerfile),
   and mirrored in the CI `go-build` job in
   [.github/workflows/ci.yml](../../.github/workflows/ci.yml).
2. **Dependency grep in CI.** The `go-lint-test` job fails the build if
   `grep -iE 'openssl|boring|native-tls' go.mod go.sum` matches
   anything. This catches a future dep pulling a CGO-crypto library
   transitively before it lands on `main`.
3. **Explicit trust stores for service-to-service.** For API ↔
   orchestrator mTLS ([internal/tls/mtls.go](../../internal/tls/mtls.go))
   we build an explicit `x509.CertPool` from the cert directory rather
   than inheriting the system trust store. Public-internet TLS
   (outbound webhooks, JWKS, ACME) uses the system CA bundle via
   stdlib defaults.

**On drift:** if a future dep upgrade pulls an OpenSSL-family crate
transitively, CI will fail loudly. At that point the fix is either to
swap the offending library or — if there's no reasonable alternative —
to add an explicit carve-out entry to this document with justification
and notify a sibling service. Do not silently mask the grep.

### Upstream OSS services — carved out by design

Vectis Mail is a multi-container stack. Five containers run upstream C
codebases that link `libssl`:

| Container | TLS responsibility | Why it's carved out |
|---|---|---|
| **vectis-postfix** | SMTPS (465), STARTTLS (25/587) | 25+ years of audited TLS code. Replacing Postfix is not on the roadmap — architecture v1.4 is frozen and the entire mail flow (ADR-008, ADR-010, Spec C) is built around it. |
| **vectis-dovecot** | IMAPS (993), POP3S (995), ManageSieve TLS | Same. Postfix's delivery partner; replacing one means replacing both. |
| **vectis-rspamd** | Outbound HTTPS to RBLs, DMARC reporting | C codebase, upstream dep. |
| **Traefik** | ACME challenges (HTTP-01 / DNS-01) | Go (`crypto/tls`); same posture as a sibling service. Single ACME flow for both HTTP and mail. |
| **vectis-cert-extractor** (sidecar) | Parses Traefik's `acme.json`, writes PEM, HUPs mail containers on rotation | Go (`crypto/tls`); minimal blast radius; replaces the former `acme.sh` sidecar (see ADR-009). |
| **vectis-webmail** (Roundcube) | IMAPS to Dovecot from PHP | Upstream PHP + libssl. |

**Maintenance commitment:** these services stay current via their
Alpine/Debian base-image updates. Container images are rebuilt on
upstream security updates. TLS configuration is hardened at the
application level (see Postfix TLS hardening notes in recent commit
history) — modern cipher list, TLS 1.2+ required for submission,
`smtpd_tls_security_level = may` on port 25 per RFC 3207.

**What the carve-out does not authorise:** adding a new C-based
service with fresh OpenSSL surface in 2026+. The carve-out is for
existing upstream MTA stack components, not a general exemption from
the policy.

## Interop

- **a sibling service → Vectis Mail** (planned V1.1 SMTP via `lettre` +
  `tokio1-rustls-tls`): handled by vectis-postfix. TLS 1.2+ with modern
  ciphers accepts rustls and OpenSSL clients identically.
- **ValidonX → Vectis Mail** (PHP/Guzzle/curl/OpenSSL): handled by
  vectis-postfix. Same path; no policy tension because ValidonX is
  consuming, not embedding, Vectis TLS.
- **Vectis → external services** (Let's Encrypt ACME, webhook targets,
  JWKS endpoints): Go stdlib `crypto/tls` via `net/http`. Standard
  modern HTTPS.

## Compliance artefact checklist

Exactly the four items ratified with a sibling service on 2026-04-17:

- [x] `grep -iE 'openssl|boring|native-tls' go.mod go.sum` returns
      empty — verified in CI.
- [x] `CGO_ENABLED=0 go build -tags netgo,osusergo` for both Go
      binaries — see Dockerfiles and CI.
- [x] This document.
- [x] Git commit introducing this policy (in lieu of a standalone
      CHANGELOG — Vectis uses git history as its changelog, per
      `BUILD_CONTEXT.md`).

## Escalation

If anyone proposes a change that would add OpenSSL-family surface to
the first-party Vectis codebase — or a new C-based service container
without a strong architectural justification matching the carve-outs
above — escalate before merging. The policy is a commitment, not a
default that drifts.
