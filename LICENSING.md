# Licensing

Vectis Mail is **source-available** under the [Business Source License 1.1](LICENSE)
and ships with a **free Starter tier** that does not require any commercial
subscription.

This document explains:

- What the licence permits
- How the Free / Pro / Enterprise tiers map onto the licence terms
- How feature gating is enforced technically
- What to expect when running self-hosted

## The licence in one paragraph

You can read, modify, and redistribute the source. You can run Vectis Mail in
**non-production** environments (dev, staging, testing, evaluation, training,
demonstration, education, personal experimentation) without any subscription
or further permission. You can run Vectis Mail in **production for your own
organisation's internal needs** within the Starter tier's resource limits
(up to 3 domains, 25 mailboxes per domain) without a subscription. To run
Vectis Mail in production above those limits, you need a Vectis subscription
(see [vectismail.com/pricing](https://vectismail.com/pricing)). You cannot
offer Vectis Mail as a hosted, embedded, or managed service that competes with
Veltara Works's paid offerings without separate commercial terms.

Four years after each version is published, that version automatically
converts to the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0)
— the BSL is a time-locked transition, not a permanent restriction.

For binding terms, read [`LICENSE`](LICENSE). For interpretive questions,
contact `legal@veltaraworks.com`.

## Tiers

### Starter — Free

- Up to **3 domains**
- Up to **25 mailboxes per domain**
- Full mail stack (Postfix, Dovecot, Rspamd, DKIM/SPF/DMARC)
- Full webmail (Roundcube with Vectis skin)
- Sending API (single + batch), inbound webhooks
- Admin UI, audit log, backups, monitoring
- Atomic updates with rollback
- No subscription required

### Pro — USD $29 / tenant / month

- **Unlimited** domains and mailboxes
- Per-domain analytics
- OIDC SSO
- Custom branding (logo, accent colour, webmail skin)
- Advanced spam configuration (per-domain reject thresholds, greylisting)
- Priority email support
- One Pro subscription covers **every** Vectis installation your organisation
  operates

### Enterprise — POA

- Multi-tenant isolation
- SLAs and named support contact
- Advanced compliance features
- See [`docs/notes/enterprise-readiness.md`](docs/notes/enterprise-readiness.md)
  for the in-flight feature roadmap

## How gating is enforced (technical detail)

This section is for engineers, security reviewers, and anyone wondering
whether patching a line in the source bypasses the paywall. Short answer:
**no, the gates are server-side.**

### Architecture

Licensing is enforced by middleware in `internal/validonx/`. On every request
to a gated endpoint, the API:

1. Reads the configured **license key** from `/etc/vectis/secrets.yaml`.
2. Looks up the cached tier + feature set in Postgres (5-minute TTL).
3. On cache miss or expiry, calls
   `POST https://api.validonx.com/api/v1/integration/licensing/resolve` with
   an `X-API-Key` header (per-domain egress key, not the license key) and the
   license key in the body.
4. ValidonX returns `{valid, status, tier, allowed_features[],
   grace_period_ends_at}`.
5. The result is cached. If subsequent ValidonX calls fail, the cache is
   served until `grace_period_ends_at` passes; after that, the install
   drops to Free tier and 403s any Pro request.

### Why patching the client doesn't unlock Pro

The React admin UI also reads the feature list and disables form inputs the
user isn't entitled to use. **These checks are cosmetic.** Even if you patch
the React build to enable disabled inputs, the underlying API request hits
a server-side gate (`FeatureGate` / `HasFeature` middleware) that re-validates
against the same cached + ValidonX-validated tier. The server rejects with
`HTTP 403 FEATURE_NOT_AVAILABLE` and no state changes.

Patching the server-side check is technically possible if you compile from
source — same as every BSL / source-available product. **Doing so violates
the BSL's Additional Use Grant** for any production use above Starter limits,
which is the licence's actual enforcement layer. Pro subscribers buy clean
licensing and update-channel access, not unbreakable DRM.

### What happens if ValidonX is unreachable

- A previously-valid license cached within the last 5 minutes continues to
  work normally.
- Past 5 minutes, the gate consults the cached `grace_period_ends_at`
  timestamp. If it's still in the future, the cache is served and a warning
  is logged.
- Past `grace_period_ends_at`, the install drops to Free tier. Pro features
  return 403 until ValidonX returns or the licence is reactivated.

### What happens if the license is cancelled or expired

ValidonX returns `valid: false` with a status of `canceled`, `expired`,
`past_due`, `paused`, or `revoked`. The gate denies non-Starter features
immediately on the next cache refresh (within 5 minutes).

### Unconfigured installs

An install without a configured ValidonX license key runs as **Free tier
only** — every non-Starter feature is denied. (The earlier "unconfigured
bypass" bug was fixed in v0.1.6 and is guarded by
`internal/validonx/gate_unconfigured_test.go`.)

## Self-hosting and ValidonX

ValidonX is currently a hosted service operated by Veltara Works. Subscribers
get a license key at checkout and paste it into the Admin UI's License page.
Operators running Vectis Mail purely on the Starter tier don't need to
configure ValidonX at all — the gate refuses non-Starter features without it.

If you're interested in fully air-gapped or self-hosted licensing, get in
touch at `licensing@veltaraworks.com`.

## Contact

- **Licence interpretive questions:** `legal@veltaraworks.com`
- **Commercial / volume / enterprise terms:** `licensing@veltaraworks.com`
- **Compliance, audit, procurement:** `legal@veltaraworks.com`
