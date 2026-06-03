# Audit Process

Standard process for conducting in-repo audits of Vectis Mail.

## When to run an audit

- **Pre-flip / pre-release** — before any irreversible production change (billing live-flip, major version cut, infrastructure migration).
- **Quarterly hardening review** — keeps drift visible even without a triggering event.
- **Comprehensive full-codebase review** — periodic deep review of the entire codebase.
- **Post-incident** — focused audit of the affected subsystem.

## Phase model

A full audit covers nine phases. Smaller audits may run a subset.

1. **Critical pre-flip security boundary** — code path affected by the triggering change.
2. **Dependency & supply chain** — vulnerability scans, license compatibility, supply-chain risk indicators.
3. **Static analysis (SAST)** — Semgrep, CodeQL, OWASP-aligned patterns.
4. **Legal / IP / license** — license map, IP risk, BSL/AGPL/SSPL compliance.
5. **Data privacy & compliance** — PII inventory, GDPR posture, encryption at-rest/in-transit, PCI scope.
6. **Code quality & architecture** — ADR adherence, test coverage, complexity, duplicate code.
7. **Performance & capacity posture** — passive review of resource limits, queue sizing, query patterns.
8. **Release readiness / SDLC / config** — backup/restore, migration safety, CI/CD pipeline, Cloudflare zone.
9. **SEO / AEO / GEO / LLMO** — content discoverability and AI-search posture.

## Tools

Read-only by default. Active probes (DAST, load tests) require explicit narrow authorisation.

| Surface | Tools |
|---|---|
| Go | `govulncheck` (source + binary modes), `go list -m all`, `go mod why` |
| npm | `npm audit --json` |
| Docker | `trivy` or `docker scout` if installed; manual pin review otherwise |
| SAST | Semgrep, CodeQL |
| Code structure | trailmark |
| Duplicate code | jscpd |
| Cloudflare zone | in-house cloudflare-audit skill |

## Severity rubric

| Severity | Definition |
|---|---|
| **Critical** | Direct production exposure today. Customer-facing impact (data loss, RCE, auth bypass). Fix before triggering event proceeds. |
| **High** | Real risk, reachability-bounded today but one config change away from Critical. Fix in the current release cycle. |
| **Medium** | Hardening opportunity. Fix in the next 1-2 releases. |
| **Low** | Cosmetic or defence-in-depth. Fix when convenient. |
| **Info** | Verified-clean / no-action — captured for auditor benefit. |

## Verdict semantics

Each phase emits one of:

- **GO** — no Critical or High findings on the in-scope surface.
- **GO-WITH-CONDITIONS** — Critical/High findings exist but customer impact is reachability-bounded, with explicit conditions to address within a stated timeframe. Conditions must be enumerable and verifiable.
- **HOLD** — at least one finding is a true blocker; triggering event must NOT proceed until fixed.

The audit's aggregate verdict is the worst phase-verdict (HOLD > GO-WITH-CONDITIONS > GO).

## Output structure

Each audit run produces a single folder containing:

- `INDEX.md` — trigger, scope summary, phase verdicts, final aggregated verdict.
- `phase-N-<short-name>.md` — one per phase.
- `remediation.md` — finding-by-finding fix tracking.
- `signoff.md` — final go/no-go with date and approver.
- `evidence/` (optional) — sanitised scan output, screenshots.

Before any commit, the rules in [`SANITIZATION.md`](./SANITIZATION.md) apply.

## Commit cadence

One commit per phase report. Each commit message follows the form:

```
audit/<audit-id>: phase N — <short phase name>

Verdict: <GO|GO-WITH-CONDITIONS|HOLD>. <one-line summary>
```

The remediation and signoff files get separate commits as they evolve.
