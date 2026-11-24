# Update notifications (v0.1.66)

Vectis tells the operator when a newer release exists, so nobody has to go
looking.

## What happens

- **Once a day** (the first check runs 5–30 minutes after the API starts, then
  every 24 hours) the API asks the orchestrator for the latest release on the
  configured channel (`releases.json`, the stable channel, by default).
- The orchestrator downloads the public release manifest and its signature from
  `dl.vectismail.com` and verifies them exactly as `vectis update` does: the
  Ed25519 signature, that the manifest belongs to the channel it was fetched
  from, and that it isn't older than the running version. A forged, replayed or
  wrong-channel manifest is recorded as a failed check, never as "up to date" or
  as a bogus update.
- **When a newer release exists:**
  - the admin **dashboard** shows a banner with a link to the Updates page and
    the release notes;
  - the **Updates** page shows a Release Check card (last check, latest release,
    any error);
  - the **admin address** (`api.admin_email` in secrets.yaml) is **emailed once
    per new release**, with the dashboard link and the `vectis update` commands.
    A failed send is retried at the next check.
- Nothing is installed automatically. Updating stays a deliberate step
  (Updates → Plan Update → Apply Update, or `sudo vectis update plan` /
  `sudo vectis update apply`).

## What is sent

Only a plain HTTPS GET of the two public files (`releases.json` and
`releases.json.ed25519`). No install identifier, licence key, hostname, mailbox
or usage data is included. Like any download, the request reaches the download
host (Cloudflare) with the server's IP address.

## Turning it off

**On the dashboard (normal way):** Updates → Release Check has two switches,
"Check daily for new releases" and "Email me about new releases". They're
saved in the database (`update_check_config`, migration 000028), take effect at
the next check without a restart, and turning the check back on runs a check
straight away. Each change is audit-logged (`updates.settings.update`).

**Locked off in `/etc/vectis/config.yaml` (air-gapped servers):**

```yaml
updates:
  check: false   # no daily check at all (also no banner or email); the dashboard switch shows as locked
  email: false   # keep the banner, never email; the email switch shows as locked
```

An explicit `false` here always wins over the dashboard. (`true` is the same as
leaving it out, so the dashboard can still turn it off.) The API reads
config.yaml at start-up, so after editing it run `sudo vectis config apply` and
`sudo docker restart vectis-api`.

With the check off, a previously stored "update available" is no longer shown,
and Updates → Plan Update still checks by hand.

**Before migration 000028 has run** (a server updated from v0.1.65 by an
orchestrator that predates it), the switches are hidden and config.yaml alone
applies. The migration runs at the following update, or by hand (see
`feedback_cross_version_migration_ordering`).

## Implementation

- `internal/orchestrator/latest_release.go`: read-only `GET /internal/release/latest`;
  reuses `fetchReleaseManifest` (the same trust checks as Plan).
- `internal/updatecheck`: the daily loop; it reads the effective switches
  (`Effective(config.yaml, update_check_config row)`) at the start of every run.
  The check RESULT (last answer and the "already emailed" version) lives in
  Valkey under `vectis:update-check:state`; if that key is ever lost, the worst
  case is one repeat email.
- The check skips the manifest's anti-rollback floor (nothing is pulled): a
  canary running an rc ahead of stable sees an older stable manifest as "no
  newer release", not as a failed check.
- `GET /api/v1/system/updates` (super_admin): the switches + last check, for the UI.
  It never triggers a fetch. `PUT /api/v1/system/updates/settings`
  (`{"check_enabled":bool,"email_enabled":bool}`, either optional) saves the
  switches; 409 `SETTING_LOCKED` if config.yaml locks it, 409
  `SETTING_UNAVAILABLE` before migration 000028.
- Config: `updates.check` / `updates.email` (explicit `false` locks off).
