# Operator guide: email engagement tracking and GDPR

Vectis Mail can record **open** and **click** events for outbound messages
that were sent with tracking markers (a 1×1 pixel and/or wrapped links). When
an event is recorded, Vectis stores the recipient's **IP address** and
**user-agent** in the `email_events` table, keyed by message ID.

Under the GDPR an IP address is personal data (Recital 30), and you — the
operator — are the **data controller** for your end users. That means you need
a lawful basis to record this data, and recipients generally have a right to
know they are being tracked.

## Default: OFF

Engagement-event recording is **disabled by default**. With it off:

- the tracking pixel still returns a transparent image, and
- tracked links still redirect to their target,

but **no IP / user-agent / event row is written**. This is the privacy-safe
default and is what fresh installs (and installs upgrading from before this
change) get unless they opt in.

## Enabling it

Set the following in `/etc/vectis/config.yaml`, then `vectis apply` (or restart
the api container):

```yaml
tracking:
  enabled: true
```

Only enable this if you have established a lawful basis for processing
recipient IP/user-agent data for your audience.

## If you enable it — operator obligations (not legal advice)

- **Lawful basis.** Decide and document yours (consent or legitimate interest
  with a balancing test are the common routes).
- **Transparency.** Tell recipients they may be tracked — e.g. a footer link
  such as "Why was this email tracked?" pointing at your privacy notice.
- **Right to erasure / access.** Recipient data lands in `email_events`
  (joined to `messages` by `message_id`). Be able to find and delete it on
  request. Deleting a mailbox now also purges its on-disk mail (see the
  delete-mailbox erasure behaviour), but `email_events` rows are keyed by
  message, not mailbox — handle those separately.
- **Retention.** `email_events` has no automatic TTL yet; prune it on a
  schedule that matches your retention policy.

## What is stored when enabled

| Field | Source | Notes |
|---|---|---|
| `ip_address` | recipient IP (honours `X-Forwarded-For` behind Traefik) | personal data |
| `user_agent` | recipient mail/web client UA string | personal data |
| `event_type` | `open` or `click` | — |
| `target_url` | click destination (click events only) | — |
| `message_id` | links the event back to the sent message | — |
