# Security Policy

## Reporting a vulnerability

If you believe you have found a security vulnerability in Vectis Mail,
please report it privately. **Do not open a public GitHub issue.**

Send a report to **`security@vectismail.com`** with:

- A description of the issue and its potential impact.
- Steps to reproduce, including the affected version (output of
  `vectis version`).
- Any proof-of-concept code or sample input you have.
- Whether you'd like to be credited in the fix announcement (and if so,
  how — name + URL).

You should receive an acknowledgement within **2 business days** (Veltara
Works is currently based in AEST). If you don't hear back, please follow
up; mail filters can be over-zealous.

## Disclosure timeline

We aim to:

- **Acknowledge:** within 2 business days.
- **Initial assessment:** within 5 business days (severity + scope).
- **Fix released:** within 30 days for high-severity issues, 90 days for
  lower-severity.
- **Public disclosure:** coordinated with the reporter, typically 7 days
  after the patched release is available.

Exceptions to the above (e.g. actively-exploited zero-days, vulnerabilities
in upstream components) will be communicated directly with the reporter.

## Scope

In scope:

- The Vectis Mail orchestrator, API, and Admin UI (this repository).
- The container images published to `ghcr.io/veltara-works/vectis-*`.
- The installer script at `dl.vectismail.com/latest/install.sh`.
- The official marketing site at `vectismail.com`.

Out of scope (please report directly to the upstream maintainer):

- Vulnerabilities in Postfix, Dovecot, Rspamd, Postgres, Valkey, Traefik,
  or other upstream containerised dependencies — these have their own
  security teams.
- Vulnerabilities in third-party integrations (ValidonX, Stripe) — report
  to the integration owner.
- Issues that require physical or root access to the host already.

## Supported versions

Security fixes are issued for the **two most recent minor releases**
(currently 0.1.x → forward). Older releases will receive security fixes
only on a best-effort basis.

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |
| < 0.1   | ❌ (pre-GA) |

## Hardening recommendations

For operators running Vectis Mail in production:

- Keep your installation on a supported release; the orchestrator's Apply /
  Update flow ships patched images.
- Restrict access to `/etc/vectis/secrets.yaml` (the installer sets mode
  `0600`; verify after any manual edit).
- Restrict access to the orchestrator UI to trusted networks; Vectis Mail
  is designed for a single trusted operator group, not anonymous public
  access.
- Subscribe to release notifications by watching this repository.
- Enable backups (`vectis backup schedule`) and test restore quarterly per
  [`docs/notes/disaster-recovery-runbook.md`](docs/notes/disaster-recovery-runbook.md).

## PGP

If you'd like to encrypt your report, request a public key in your initial
email to `security@vectismail.com` and we'll provide one and a fingerprint.

## Hall of fame

Researchers credited with responsibly disclosing vulnerabilities will be
listed in release notes (with permission). We currently don't run a paid
bug bounty programme, but we'll consider one as the user base grows.

---

*Thank you for keeping Vectis Mail users safe.*
