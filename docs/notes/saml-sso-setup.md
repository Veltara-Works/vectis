# SAML 2.0 SSO — operator setup guide

SAML single sign-on lets your admins authenticate to the Vectis Mail admin UI
through your corporate identity provider (IdP) — Okta, Microsoft Entra ID
(Azure AD), or Active Directory Federation Services (ADFS).

> **Enterprise feature.** SAML SSO requires an active Enterprise licence
> (`saml_sso`). On Free/Pro installs the SAML login buttons and Service Provider
> metadata are suppressed, and the login/ACS routes return a 402/403. OIDC SSO
> remains available on Pro.

## How it works (at a glance)

- **SP-initiated only.** The admin clicks a provider button on the login page;
  Vectis (the Service Provider, "SP") builds a *signed* AuthnRequest and
  redirects the browser to your IdP. After the IdP authenticates the user it
  POSTs a signed assertion back to the SP's Assertion Consumer Service (ACS).
- **No JIT provisioning.** A matching admin account must already exist in
  Vectis (matched first by SAML subject, then by email). The first successful
  login *links* the SAML identity to that admin; there is no auto-create. Create
  the admin under **Admins** first. This mirrors the OIDC behaviour.
- **One SP identity per install.** A single SP keypair (entityID + cert + key)
  is shared across every configured provider.
- **Federated logins skip TOTP**, same as OIDC — your IdP owns MFA.

The SP validates every assertion's **signature**, **audience** (must equal the
SP entityID), **time window** (NotBefore / NotOnOrAfter, with clock skew),
**recipient** (must equal the ACS URL), **InResponseTo** + **RelayState** (CSRF),
and enforces **single-use replay protection** via Valkey.

## URLs you will need

With your install reachable at `https://mail.example.com`, and a provider you
name `okta`, the SP exposes:

| Purpose            | URL                                                                 |
| ------------------ | ------------------------------------------------------------------- |
| SP metadata (XML)  | `https://mail.example.com/api/v1/auth/saml/metadata/okta`           |
| ACS (POST binding) | `https://mail.example.com/api/v1/auth/saml/acs/okta`                |
| SP-initiated login | `https://mail.example.com/api/v1/auth/saml/login/okta`             |
| SP entityID        | whatever you pass to `--entity-id` below (e.g. `https://mail.example.com/saml/metadata`) |

The metadata, ACS, and login URLs are **per-provider** — the trailing path
segment is the provider key from your `secrets.yaml`. The SP entityID is a
single value shared across providers.

You can download the SP metadata XML from the admin UI under
**Single Sign-On → Service Provider (SP) metadata → Download SP metadata**
(super_admin only), or fetch the metadata URL above directly.

## Step 1 — Generate the SP keypair

Run once per install. The cert is published in your SP metadata; the private key
signs AuthnRequests.

```sh
vectis saml init-sp --entity-id "https://mail.example.com/saml/metadata"
```

This prints a ready-to-paste `saml:` block (a self-signed 2048-bit RSA keypair,
10-year cert). Rotate by re-running and replacing the block.

## Step 2 — Configure `secrets.yaml`

Paste the generated block under a top-level `saml:` key in
`/etc/vectis/secrets.yaml`, then add one entry per IdP under `providers:`:

```yaml
saml:
  sp_entity_id: "https://mail.example.com/saml/metadata"
  sp_private_key: |
    -----BEGIN RSA PRIVATE KEY-----
    ...
    -----END RSA PRIVATE KEY-----
  sp_certificate: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
  providers:
    okta:
      enabled: true
      idp_metadata_url: "https://YOUR-ORG.okta.com/app/XXXX/sso/saml/metadata"
      email_attr: "email"        # optional; default "email"
```

Provider fields:

| Field              | Notes                                                                          |
| ------------------ | ------------------------------------------------------------------------------ |
| `enabled`          | Set `true` to expose the provider. Disabled providers are not listed or served. |
| `idp_metadata_url` | **Preferred.** Fetched at startup. Auto-tracks IdP cert rollover.               |
| `idp_metadata_xml` | Air-gapped alternative — paste the IdP metadata XML inline instead of a URL.    |
| `email_attr`       | Optional. The assertion attribute carrying the user's email when it is not the NameID. Defaults to `email`. |

Supply **either** `idp_metadata_url` **or** `idp_metadata_xml`, not both. The
provider key (`okta` here) becomes the trailing segment in the per-provider URLs.

Apply the change:

```sh
vectis config apply
```

The API picks up SAML at startup; the login page will show the provider button
once the install is Enterprise-entitled.

## Step 3 — Register the SP at your IdP

Hand the IdP your **SP metadata** (download it from the admin UI or fetch the
metadata URL). If your IdP cannot import metadata, configure manually:

- **Audience / SP entityID:** the `sp_entity_id` value.
- **ACS / Reply / Single Sign-On URL:** `https://mail.example.com/api/v1/auth/saml/acs/<provider>`.
- **Binding:** HTTP-POST.
- **Signing:** the SP signs AuthnRequests with the cert from your metadata. The
  IdP **must sign assertions** (the SP rejects unsigned/badly-signed assertions).
- **NameID:** email address (or map an `email` attribute and set `email_attr`).

### Okta

1. Admin console → **Applications → Create App Integration → SAML 2.0**.
2. **Single sign-on URL** = the ACS URL; check *Use this for Recipient/Destination*.
3. **Audience URI (SP Entity ID)** = your `sp_entity_id`.
4. **Name ID format** = EmailAddress; map `email` under Attribute Statements if needed.
5. Assign the app to the users/groups who should have admin access.
6. Copy the app's **Identity Provider metadata** URL into `idp_metadata_url`.

### Microsoft Entra ID (Azure AD)

1. **Enterprise applications → New application → Create your own → Non-gallery**.
2. **Single sign-on → SAML**.
3. **Identifier (Entity ID)** = your `sp_entity_id`.
4. **Reply URL (ACS)** = the ACS URL.
5. Under **Attributes & Claims**, ensure the email claim is emitted (or set
   `email_attr` to match the claim name).
6. Copy **App Federation Metadata Url** into `idp_metadata_url`. Assign users.

### ADFS

1. **AD FS Management → Relying Party Trusts → Add Relying Party Trust**.
2. Import the SP metadata (URL or downloaded file).
3. Add a **Claim Issuance** rule mapping the user's email to the NameID
   (EmailAddress) — or to an `email` attribute matched by `email_attr`.
4. ADFS has no public metadata URL in air-gapped setups — export the ADFS
   federation metadata and paste it into `idp_metadata_xml`.

## Step 4 — Link an admin and test

1. In **Admins**, confirm an admin exists whose email matches what the IdP will
   assert (or who will present a matching SAML subject).
2. Sign out, then click the provider button on the login page.
3. After the IdP round-trip you land on `/admin`, authenticated. The audit log
   records `auth.saml.login`.

## Disconnecting / unlinking

Each admin can unlink their own SAML identity under **Single Sign-On → Your SSO
identity → Disconnect** (audit event `auth.saml.disconnect`). The disconnect is
**refused** if the account has no password set, to prevent lockout — set a
password first.

## Troubleshooting

| Symptom                                          | Likely cause                                                                 |
| ------------------------------------------------ | --------------------------------------------------------------------------- |
| No SAML buttons on the login page                | Install not Enterprise-entitled, provider `enabled: false`, or no providers. |
| `SAML_NO_ACCOUNT` (403) after IdP login          | No Vectis admin matches the asserted subject/email — create the admin first. |
| `SAML_AUTH_FAILED` (401)                         | Assertion signature/audience/recipient/time-window/replay check failed. Confirm the IdP signs assertions, the ACS URL matches exactly, and clocks are in sync. |
| `SAML_PROVIDER_NOT_FOUND` (404)                  | Provider key in the URL doesn't match a configured, enabled provider.        |
| Login redirects but IdP rejects the request      | SP entityID / ACS URL registered at the IdP doesn't match this install's metadata. Re-import the SP metadata. |

## Related

- OIDC SSO (Pro) follows the same account-linking model.
- API routes: see `docs/spec/A_API_Endpoint_Inventory.md`.
