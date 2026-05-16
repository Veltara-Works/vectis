# Sanitisation Rules

Every audit artifact passes through these rules before it is checked in. The repo is private, but assume future buyers and external reviewers will read everything in `docs/audits/`. **Treat anything checked in as eventually-public.**

## What MUST NOT be checked in

| Category | Action |
|---|---|
| **Credentials of any kind** | Passwords, API keys, OAuth tokens, session cookies, SSH private keys, PEM private keys, encrypted secret blobs. **Never.** |
| **Internal IPs** | Docker network ranges, BinaryLane internal addresses, anything not resolvable from a public DNS query. |
| **Customer PII** | Real customer email addresses, names, phone numbers, real tenant UUIDs that map to paying customers. |
| **Build-VPS paths** | `/home/<user>/`, `.claude/`, `/etc/vectis/secrets.yaml` paths — never appear in committed artifacts. They leak the build user and the secrets directory location. |
| **Other-repo absolute paths** | Use repo-prefix form: `vectismail.com/functions/account/billing.ts`, not `/home/<user>/vectismail.com/functions/account/billing.ts`. |
| **Other-org details** | Partner internal endpoints, API-key prefixes, contractual terms — only with explicit partner consent. |
| **Raw scan output** | Sanitised version only. Raw output goes to `evidence-raw/` (gitignored). |
| **Screenshots with credentials visible** | Crop or redact browser address bars, dev tools, environment panels. |

## What IS OK

| Category | Notes |
|---|---|
| **Repo-relative file:line refs** | `internal/api/handle_license.go:207` — yes. |
| **CVE / advisory IDs** | `GHSA-v2wj-q39q-566r`, `CVE-2025-12345` — yes. |
| **Architecture findings** | "Cache TTL is 5 minutes," "audit-log emission missing on failure branch" — yes. |
| **Public IPs already in DNS** | `mail.vectismail.com → 103.100.36.241` is already public; fine to document. |
| **The user's own email / tenant** | Your own data is fine — verify it's yours before checking in. |

## Pre-commit grep

Run before every audit-related commit. Any match → review and remove before committing.

The grep commands below use a git pathspec exclusion (`:!...SANITIZATION.md`) to skip this file itself; otherwise the example patterns documented here would self-trigger as false positives.

```bash
# Credential patterns
git diff --cached -- 'docs/audits/' ':!docs/audits/_docs/SANITIZATION.md' \
  | grep -E '(sk_live_|sk_test_|pk_live_|pk_test_|vectis_[0-9a-f]{8}|xox[abp]-|ghp_|gho_|ghu_|ghs_|ghr_|AKIA[A-Z0-9]{16}|AGE-SECRET-KEY-1|-----BEGIN (OPENSSH|RSA|EC|DSA|PGP) PRIVATE KEY-----)'

# Build-VPS path leaks
git diff --cached -- 'docs/audits/' ':!docs/audits/_docs/SANITIZATION.md' \
  | grep -E '(/home/[a-z][a-z0-9-]+/|\.claude/|/etc/vectis/secrets)'

# 32-char-hex-near-secret-keyword (e.g. Cloudflare-style API keys)
git diff --cached -- 'docs/audits/' ':!docs/audits/_docs/SANITIZATION.md' \
  | grep -iE '(key|token|secret|password)[^a-z0-9]*[a-f0-9]{32}'
```

## Specific known-credential shapes

Treat these as poison. If ANY appear in an audit artifact, the artifact was generated without sanitisation:

- `vectis_<hex>` — ValidonX partner key prefix.
- 32-character lowercase hex strings adjacent to a "key/token/secret/password" keyword — likely a Cloudflare-style API key.
- Any string between `-----BEGIN ...-----` and `-----END ...-----` markers.

## Reviewer checklist

Before any audit commit lands:

- [ ] Pre-commit grep clean (run all three checks above)
- [ ] All file paths repo-relative
- [ ] No `/home/<user>/` or `/opt/vectis/` prefixes (paths are relative to the repo root)
- [ ] Real customer data redacted or replaced with `<redacted>`
- [ ] Raw scan files are in `evidence-raw/` (gitignored), not `evidence/`
- [ ] No private keys, regardless of which system they're from
