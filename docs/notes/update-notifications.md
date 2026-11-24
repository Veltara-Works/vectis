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

In `/etc/vectis/config.yaml`:

```yaml
updates:
  check: false   # no daily check at all (also no banner or email), e.g. air-gapped servers
  email: false   # keep the dashboard banner, but don't email the admin
```

Then `sudo vectis config apply`. With the check off, Updates → Plan Update still
checks by hand.

## Implementation

- `internal/orchestrator/latest_release.go`: read-only `GET /internal/release/latest`;
  reuses `fetchReleaseManifest` (the same trust checks as Plan).
- `internal/updatecheck`: the daily loop. State (last result and the
  "already emailed" version) lives in Valkey under `vectis:update-check:state`,
  not in Postgres, so the feature needs no migration. If that key is ever lost,
  the worst case is one repeat email.
- `GET /api/v1/system/updates` (super_admin): the last check, for the UI. It never
  triggers a fetch.
- Config: `updates.check` / `updates.email`, both default `true`.
