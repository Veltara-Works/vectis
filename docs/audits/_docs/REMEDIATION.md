# Remediation Tracking

How audit findings flow from "discovered" to "closed."

## Finding ID format

`<audit-date>-P<phase-number>-<severity-letter><sequence>`

Examples:
- `2026-05-17-P1-M1` — first Medium finding in Phase 1 of the 2026-05-17 audit.
- `2026-05-17-P2-H2` — second High in Phase 2.

Severity letters: `C` (Critical), `H` (High), `M` (Medium), `L` (Low). Info findings are not tracked here.

## Status states

| Status | Meaning |
|---|---|
| **OPEN** | Discovered, not yet started. |
| **IN-PROGRESS** | Fix being implemented. Link to PR/branch. |
| **RESOLVED** | Fix merged + verified. Link to commit. |
| **WONT-FIX** | Decision not to fix, with documented reason. |
| **DEFERRED** | Acknowledged, planned for a specific later release or date. |

## Tracking format

In each audit's `remediation.md`:

```
### 2026-05-17-P2-H2 — Vite 8.0.3 build-chain vulns
- Severity: High
- Discovered: 2026-05-17 (Phase 2)
- Status: RESOLVED
- Resolved-by: <commit-sha>
- Resolved-date: 2026-05-17
- Verification: `npm audit` in web/ reports zero vulns post-fix
- Note: Build-chain only; never reached production runtime.
```

## When to close

- **RESOLVED** requires: fix in repo, regression test if applicable, verification that the finding no longer reproduces.
- **WONT-FIX** requires: written rationale (why fix > cost, impossible, or out of scope).
- **DEFERRED** requires: target release or date.

## External dependencies

If a finding requires an external party (e.g., ValidonX) to fix, mark it `DEFERRED` with an explicit external-owner note and link to the coordination thread or memory.
