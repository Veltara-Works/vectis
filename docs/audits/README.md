# Audits

In-repo audit trail for Vectis Mail. Each subdirectory under this folder is a single audit run — pre-release milestones, security reviews, due-diligence preparation, or compliance attestation.

The repo is private; treat anything checked in here as eventually-public anyway, and observe `_docs/SANITIZATION.md` before every commit.

## How to read this folder

- [`_docs/PROCESS.md`](./_docs/PROCESS.md) — how an audit is conducted, the phase model, tools, severity rubric, verdict semantics.
- [`_docs/SANITIZATION.md`](./_docs/SANITIZATION.md) — what must be redacted before any audit artifact is checked in. **Read before committing.**
- [`_docs/REMEDIATION.md`](./_docs/REMEDIATION.md) — how findings are tracked through to closure.
- [`_templates/`](./_templates/) — scaffolds for new audit runs and individual phase reports.
- Date-prefixed folders (e.g. `2026-05-17-pre-stripe-flip/`) — individual audit runs.

## Audit history

| Date | Scope | Verdict | Report |
|---|---|---|---|
| 2026-05-17 | Pre-Stripe-flip comprehensive audit (9 phases) | _In progress_ | [INDEX](./2026-05-17-pre-stripe-flip/INDEX.md) |
