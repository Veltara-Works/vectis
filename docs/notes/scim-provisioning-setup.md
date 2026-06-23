# SCIM 2.0 provisioning — operator setup guide

SCIM 2.0 lets your identity provider (IdP) — Okta or Microsoft Entra ID
(Azure AD) — automatically **create, update, and deactivate mailboxes** on your
Vectis Mail server as employees join, change, and leave. It removes the manual
step of provisioning an account before someone can sign in via SSO.

> **Enterprise feature.** SCIM requires an active Enterprise licence (`scim`).
> On Free/Pro installs the `/scim/v2` endpoints and the token-management UI
> return a SCIM-shaped **403** (`application/scim+json`). SAML SSO (`saml_sso`)
> is its natural companion — SCIM provisions the account, SAML authenticates it.

## What it does (and what it deliberately doesn't)

- **Target = mailboxes.** A SCIM `User` maps to a Vectis **mailbox**
  (`local_part@domain`), not a console admin. This matches employee email
  lifecycle: create on hire, suspend on leave.
- **Deactivate, never erase.** `active:false` *and* `DELETE` both **deactivate**
  the mailbox (`active=false`) — they never delete it. This avoids orphaning
  stored mail and conflicting with GDPR erasure, which stays a deliberate DSAR
  action (see the DSAR runbook). A deactivated mailbox stops authenticating and
  rejects new mail, but its data is retained.
- **Users only (Phase 1).** `/scim/v2/Groups` is not implemented yet — Vectis
  has no group/distribution-list primitive that maps cleanly to SCIM Groups.
  Assign group-based app access on the IdP side.
- **The domain must already exist.** SCIM cannot create a Vectis domain (DNS and
  DKIM setup is separate). Provision the domain under **Domains** first; a
  `userName` for an unknown or inactive domain is rejected with a 400.
- **Provisioned mailboxes are SSO-only by default.** A SCIM-created mailbox gets
  a random, unusable password — the user authenticates through your IdP
  (SAML/OIDC), not IMAP/SMTP basic auth. Set a password later under **Mailboxes**
  if the user needs a mail client with app credentials.

## How it works (at a glance)

- SCIM clients are machine-to-machine: they present a **static Bearer token**
  (`Authorization: Bearer scim_…`), not a session. The token is minted in the
  admin UI and is scoped to provisioning only — it can never act as an admin.
- The SP validates the token on every request, enforces the Enterprise gate,
  and responds with the `application/scim+json` media type and SCIM error
  objects (string `status`, `scimType`).
- **`externalId` is the join key.** Send your IdP's stable user id as
  `externalId`; Vectis stores it and uses it (alongside the SCIM `id` we return)
  to find the right mailbox on later update/deactivate calls, independently of
  the email address.

## URLs you will need

With your install reachable at `https://mail.example.com`:

| Purpose                 | URL                                                       |
| ----------------------- | --------------------------------------------------------- |
| SCIM base ("Base URL")  | `https://mail.example.com/scim/v2`                        |
| Users collection        | `https://mail.example.com/scim/v2/Users`                  |
| ServiceProviderConfig   | `https://mail.example.com/scim/v2/ServiceProviderConfig`  |
| ResourceTypes           | `https://mail.example.com/scim/v2/ResourceTypes`          |
| Schemas                 | `https://mail.example.com/scim/v2/Schemas`                |

Supported operations: `POST/GET/PUT/PATCH/DELETE /Users`,
`GET /Users?filter=userName eq "…"`, and the three discovery endpoints.

## Step 1 — Generate a SCIM token

1. Sign in to the admin UI as a **super_admin**.
2. Go to **Single Sign-On** → **SCIM provisioning**.
3. Click **Generate token**. The raw token (`scim_…`) and the SCIM **endpoint
   URL** are shown **once** — copy them now. Only a hash is stored; you cannot
   retrieve the token again.
4. If you ever need to rotate, click **Regenerate** — this immediately revokes
   the previous token (single active token per install) and issues a new one.
   Paste the new token into your IdP. **Revoke** turns a token off entirely.

## Step 2 — Configure your IdP

### Okta

1. In the Okta admin console, open your app → **Provisioning** → **Integration**.
2. Enable **API integration**.
3. **Base URL**: `https://mail.example.com/scim/v2`
4. **API Token**: the `scim_…` token from Step 1.
5. **Test API Credentials**, then save.
6. Under **To App**, enable **Create Users**, **Update User Attributes**, and
   **Deactivate Users**.
7. Map at minimum `userName` → the user's email (it must be
   `local_part@<a-provisioned-domain>`), and send `externalId`. Optionally map a
   display name to `name.formatted` / `displayName`.

### Microsoft Entra ID (Azure AD)

1. In **Enterprise applications** → your app → **Provisioning**, set mode to
   **Automatic**.
2. **Tenant URL**: `https://mail.example.com/scim/v2`
3. **Secret Token**: the `scim_…` token from Step 1.
4. **Test Connection**, then save and start provisioning.
5. In **Attribute mappings**, ensure `userName` maps to the email at a
   provisioned domain and `externalId` is populated. Entra deactivates via
   `PATCH active:false`, which is supported.

## Step 3 — Verify

- Assign a test user in the IdP → confirm a mailbox appears under
  **Mailboxes** for the right domain, marked active.
- Unassign / disable the user → confirm the mailbox flips to **inactive**
  (it is not deleted).
- Re-assign → the IdP reactivates the existing mailbox via `PATCH active:true`
  (Phase 1 does **not** auto-reactivate on a re-*create* — a duplicate
  `userName`/`externalId` returns **409**; reactivation is the IdP's update call).

## Lifecycle reference

| IdP action            | SCIM call                                   | Vectis effect                                  |
| --------------------- | ------------------------------------------- | ---------------------------------------------- |
| Provision user        | `POST /Users`                               | Create mailbox (random password); 409 if it exists |
| Probe before create   | `GET /Users?filter=userName eq "…"`         | `ListResponse` (empty or 1), never 404         |
| Update attributes     | `PUT /Users/{id}` / `PATCH /Users/{id}`     | Update display name / active                    |
| Deactivate            | `PATCH active:false` or `DELETE /Users/{id}`| Mailbox `active=false` (retained, not erased)  |
| Reactivate            | `PATCH active:true` (or `PUT … active:true`)| Mailbox `active=true` (found by the SCIM `id`) |
| Rename (`userName`)   | `PUT` with a changed `userName`             | **409** — rename is not supported in Phase 1   |

## Troubleshooting

- **401 on every call** — the token is missing, malformed, revoked, or expired,
  or the `Authorization` header isn't `Bearer scim_…`. Regenerate and re-paste.
- **403 on every call** — the install is not entitled to `scim` (not Enterprise,
  or the licence lapsed past its offline horizon). Check **License**.
- **400 "Domain … is not provisioned / not active"** — create and activate the
  domain under **Domains** first; `userName` must use a provisioned domain.
- **409 uniqueness** — a mailbox with that `userName` or `externalId` already
  exists. This is expected on re-onboarding: don't re-create — reactivate the
  existing user with `PATCH active:true` (most IdPs do this automatically). Send
  a stable `externalId` so re-creates are reliably detected as duplicates.
- **Token leaked?** A SCIM token can create and deactivate every mailbox.
  Regenerate immediately (this revokes the old one), and review `last_used_at`
  in the token list. Restrict IdP egress IPs where possible.

## Related

- `saml-sso-setup.md` — SAML SSO (authenticates the accounts SCIM provisions).
- DSAR runbook — GDPR access/erasure (erasure is a deliberate action, distinct
  from SCIM deactivation).
