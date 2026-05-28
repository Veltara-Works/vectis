# Operator runbook: responding to a Data Subject Access Request

This runbook helps operators of a Vectis Mail install respond to a
Data Subject Access Request (DSAR — also known as a Subject Access
Request, SAR) from one of their end users. A DSAR is the legal
mechanism under GDPR Article 15 (UK GDPR Art. 15, CCPA §1798.110,
Australian Privacy Act APP 12, and equivalents) by which a person
("data subject") can ask the operator of a service ("controller")
for a copy of all personal data the service holds about them.

> **This is not legal advice.** It is operational guidance for
> assembling the technical answer. Whether and how to respond, the
> applicable deadline (typically 30–45 days), the format the requester
> is entitled to, and any exemptions are jurisdiction-specific. Run
> the response by your privacy counsel before sending.

Closes audit finding **2026-05-17-P5-M1** (target: v0.1.13). The
lower-effort MVP of the two options the audit recommends; the higher-
effort option is the dedicated `GET /api/v1/mailboxes/{id}/dsar-export`
endpoint, deferred to a later release.

---

## Scope: what Vectis Mail holds per mailbox

For one mailbox `subject@example.com` (assume `domain_id` resolved
from `example.com` and `mailbox_id` resolved from `subject`), the
operator's Vectis install holds:

| Source | Contents | Why it's PII |
|---|---|---|
| `mailboxes` row | local part, display name, quota, created/updated timestamps, active flag | Account metadata |
| Maildir tree on disk | Every received email currently in the mailbox (Inbox, Sent, Trash, custom folders) including bodies, attachments, full headers | Communication content + correspondents' addresses |
| `messages` rows | Every sent + received message's envelope metadata (sender, recipients, subject, size, status, spam score, queue id, selected headers) | Communication metadata; recipient addresses |
| `email_events` rows (Pro engagement tracking) | Open + click events tied to messages this mailbox sent; per event: user agent, IP address, click target URL | Behavioural tracking — narrowest privacy bucket |
| `abuse_events` rows | Abuse-detection events involving this mailbox (rate spikes, anomalies, manual or auto suspensions) | Account history; may be requested for fairness |
| `fbl_reports` rows | Feedback-loop complaints filed against messages sent by this mailbox | Reputation history |
| `audit_log` rows | Admin actions performed on this mailbox (creation, password reset, suspension, deletion) — admin's address only, not the data subject's | Borderline; commonly included for completeness |

The mailbox owner's **password is stored only as a hash** (Argon2id) —
not personal data and not exportable.

---

## Step 1 — Resolve mailbox to its UUIDs

All the queries below take `:mailbox_id` (a UUID). Resolve it from
the email address first:

```sql
-- Run as a Postgres superuser, or as vectis_api via psql.
-- Replace example values.
SELECT
    m.id   AS mailbox_id,
    m.domain_id,
    d.name AS domain,
    m.local_part,
    m.display_name,
    m.quota_mb,
    m.active,
    m.created_at,
    m.updated_at
FROM mailboxes m
JOIN domains d ON d.id = m.domain_id
WHERE d.name = 'example.com'
  AND m.local_part = 'subject';
```

Capture `mailbox_id` and `domain_id` from the result for the
remaining queries.

---

## Step 2 — Export the Maildir (the bulk of the data)

The mail bodies and attachments live on disk under
`/var/vectis/mail/<domain>/<local_part>/Maildir/`. Tarball it:

```bash
# Run on the host (not inside a container).
DOMAIN="example.com"
LOCAL="subject"
SUBJECT_ID="$DOMAIN-$LOCAL"   # used in output filename
OUT_DIR="/tmp/dsar-${SUBJECT_ID}-$(date -u +%Y%m%d)"

mkdir -p "$OUT_DIR"

sudo tar -czf "$OUT_DIR/maildir.tar.gz" \
    -C "/var/vectis/mail/$DOMAIN" "$LOCAL"

ls -lh "$OUT_DIR/maildir.tar.gz"
```

This captures the data subject's actual emails. Maildir is a
plain-text on-disk format — the requester can extract the tarball
and open individual messages with any mail reader (Thunderbird,
mutt, or just `less`).

---

## Step 3 — Export the structured metadata as JSON

Vectis ships no built-in JSON export yet (P5-M1 follow-up). Use
`psql` with `\t \a \o` and `row_to_json` to emit clean JSON files
the requester can read. Run from the host:

```bash
# Substitute the mailbox_id from Step 1.
MAILBOX_ID="00000000-0000-0000-0000-000000000000"

# psql connection — pick whichever you normally use.
PSQL="docker exec -i vectis-postgres psql -U vectis_api -d vectis"
```

### 3a — Mailbox account record

```bash
$PSQL <<SQL > "$OUT_DIR/mailbox.json"
\t
\a
SELECT json_agg(row_to_json(m))
FROM (
    SELECT
        id, domain_id, local_part, display_name, quota_mb,
        active, created_at, updated_at
    FROM mailboxes
    WHERE id = '$MAILBOX_ID'::uuid
) m;
SQL
```

(Note: the `password_hash` column is intentionally excluded — it is
not personal data and disclosure would be a security weakness.)

### 3b — Sent + received messages (envelope metadata)

```bash
$PSQL <<SQL > "$OUT_DIR/messages.json"
\t
\a
SELECT json_agg(row_to_json(m) ORDER BY m.created_at)
FROM (
    SELECT
        id, message_id, direction, sender, recipients,
        subject, size_bytes, status, spam_score, spam_action,
        queue_id, headers, created_at
    FROM messages
    WHERE mailbox_id = '$MAILBOX_ID'::uuid
) m;
SQL
```

### 3c — Engagement tracking events (Pro only)

As of v0.1.16 engagement recording is **opt-in and off by default**
(finding P5-H2) — see `operator-gdpr-tracking.md`. If the operator
never set `tracking.enabled: true`, this table is empty for the
relevant period and there is nothing to export here.

`email_events` join via `message_id` (RFC 5322 Message-ID, not the
UUID). Pull events for messages the mailbox owns:

```bash
$PSQL <<SQL > "$OUT_DIR/email_events.json"
\t
\a
SELECT json_agg(row_to_json(e) ORDER BY e.created_at)
FROM (
    SELECT
        e.id, e.message_id, e.event_type, e.target_url,
        e.user_agent, e.ip_address, e.created_at
    FROM email_events e
    JOIN messages m ON m.message_id = e.message_id
    WHERE m.mailbox_id = '$MAILBOX_ID'::uuid
) e;
SQL
```

### 3d — Abuse detection events

```bash
$PSQL <<SQL > "$OUT_DIR/abuse_events.json"
\t
\a
SELECT json_agg(row_to_json(a) ORDER BY a.created_at)
FROM (
    SELECT
        id, event_type, severity, details, action,
        resolved, resolved_by, resolved_at, created_at
    FROM abuse_events
    WHERE mailbox_id = '$MAILBOX_ID'::uuid
) a;
SQL
```

### 3e — Feedback-loop reports

```bash
$PSQL <<SQL > "$OUT_DIR/fbl_reports.json"
\t
\a
SELECT json_agg(row_to_json(f) ORDER BY f.created_at)
FROM (
    SELECT
        id, original_message_id, reporter_domain,
        complaint_type, feedback_id, details, created_at
    FROM fbl_reports
    WHERE mailbox_id = '$MAILBOX_ID'::uuid
) f;
SQL
```

### 3f — Audit log entries that mention this mailbox

The `audit_log` schema stores admin actions; the data subject's row
is typically referenced in `target_id` or in the JSONB `details`.
Include it for completeness — the requester is entitled to know what
the operator did to their account:

```bash
$PSQL <<SQL > "$OUT_DIR/audit_log.json"
\t
\a
SELECT json_agg(row_to_json(a) ORDER BY a.created_at)
FROM (
    SELECT
        id, admin_id, action, resource_type, resource_id,
        details, ip_address, created_at
    FROM audit_log
    WHERE resource_type = 'mailbox'
      AND resource_id   = '$MAILBOX_ID'::uuid
) a;
SQL
```

If your install rotates audit logs externally (Loki, S3), include
that source too — see Step 5.

---

## Step 4 — Package and deliver

```bash
cd "$OUT_DIR"

# Bundle everything into one archive.
tar -czf "/tmp/dsar-${SUBJECT_ID}-$(date -u +%Y%m%d).tar.gz" .

# Encrypt before delivery. age (https://age-encryption.org) is a
# good default; gpg also fine. Use the requester's own public key.
age -r "$REQUESTER_AGE_PUBLIC_KEY" \
    -o "/tmp/dsar-${SUBJECT_ID}-$(date -u +%Y%m%d).tar.gz.age" \
    "/tmp/dsar-${SUBJECT_ID}-$(date -u +%Y%m%d).tar.gz"

# Delete the unencrypted bundle.
shred -u "/tmp/dsar-${SUBJECT_ID}-$(date -u +%Y%m%d).tar.gz"
rm -rf "$OUT_DIR"
```

Deliver the `.age` file via your normal secure-file channel (signed
download URL with short TTL, encrypted email, etc.). Do **not** mail
the unencrypted bundle.

Send a covering letter or email that:

- Confirms the legal request you're responding to (DSAR/SAR + jurisdiction).
- Lists what's in the bundle (`mailbox.json`, `messages.json`, `maildir.tar.gz`, etc.).
- Names the encryption format and how to decrypt.
- Notes any data you've withheld and the legal basis (e.g. third-party
  PII in recipient addresses, ongoing-investigation exemption, etc.).
- Records the date you completed the response (so the response-window
  clock is documented).

---

## Step 5 — Out-of-band sources to check

The queries above cover everything inside the Vectis Postgres + the
Maildir. Depending on your deployment, additional sources may hold
mailbox-related PII:

- **Loki / Grafana logs.** Mail server logs (Postfix, Dovecot) may
  contain `from=` / `to=` lines referencing this mailbox for the
  retention window. Until P7-H3 lands (drop `user` Promtail label),
  Loki indexes the user email as a label and 30-day retention applies.
- **Backup tarballs.** Encrypted backups (the operator's choice of
  schedule + retention) contain historical Maildir + Postgres state.
  Whether to include older snapshots in the DSAR depends on the legal
  request scope — usually not, but document the decision.
- **Webhook delivery history.** If the mailbox has webhooks configured,
  delivery logs include the URLs your install POSTed to. Out of scope
  for the subject (the URLs aren't their PII), but worth checking.
- **External monitoring / alerting platforms.** If you forward logs
  or alerts to a SIEM, PagerDuty, Slack, etc., those copies are
  separate controllers' responsibility — but the operator should
  acknowledge their existence in the response.

---

## Right-to-be-forgotten requests (deletion)

A separate but related request: the data subject asks for their data
to be **deleted**, not just disclosed.

As of **v0.1.16** (audit finding **P5-H1**), deleting a mailbox is a
complete on-disk erasure: after removing the DB row, the API resolves
the domain and `os.RemoveAll`s the per-mailbox directory under
`/var/vectis/mail/{domain}/{local_part}` (mail content **and** the
sieve script). The outcome is recorded in the `mailbox.delete` audit
entry as `{"maildir_purged": true|false}`. A purge failure is logged
and audited but does **not** fail the delete — the row is already
gone — so you must check the audit field and run the manual fallback
(step 2 below) if it came back `false`.

What the delete does **not** purge automatically (these tables outlive
the mailbox row by design, so erasure still needs the manual SQL):

- `messages` — `mailbox_id` is `ON DELETE SET NULL`, so envelope
  metadata survives with a null mailbox.
- `email_events` — keyed by RFC 5322 Message-ID (text), not an FK to
  the mailbox, so engagement events survive.
- `fbl_reports` — `mailbox_id` is `ON DELETE SET NULL`, survives.
- `abuse_events` — `mailbox_id` is `ON DELETE CASCADE`, so these **are**
  removed automatically with the mailbox.
- `audit_log` — retained on purpose (legal-basis exemption: legitimate
  interest in security/abuse recordkeeping). Document the decision.

```bash
# 1. Delete the mailbox (API or admin UI). As of v0.1.16 this ALSO
#    purges the on-disk Maildir + sieve automatically.
curl -X DELETE "https://mail.example.com/api/v1/mailboxes/$MAILBOX_ID" \
     -H "X-API-Key: $ADMIN_KEY"

# 1a. Confirm the Maildir was purged. If maildir_purged is false,
#     run step 2; if true, skip it.
$PSQL -c "SELECT details->>'maildir_purged' AS maildir_purged
          FROM audit_log
          WHERE action='mailbox.delete' AND resource_id='$MAILBOX_ID'::uuid
          ORDER BY created_at DESC LIMIT 1;"

# 2. Manual fallback ONLY if step 1a returned false (e.g. domain
#    lookup failed at delete time, or a pre-v0.1.16 install).
sudo rm -rf "/var/vectis/mail/example.com/subject"

# 3. Erase messages rows (survive the delete — see table above).
#    Capture their Message-IDs first if you need them for step 4.
$PSQL -c "DELETE FROM messages WHERE mailbox_id IS NULL
          AND (sender LIKE 'subject@example.com'
               OR 'subject@example.com' = ANY(recipients));"

# 4. Erase email_events for those messages' Message-IDs (grep them
#    out before step 3 — once messages are gone the join is lost).

# 5. Erase fbl_reports for the mailbox (mailbox_id SET NULL — purge
#    by domain + manual filter). abuse_events are gone via CASCADE.
```

A higher-effort future option — a dedicated
`DELETE /api/v1/mailboxes/{id}?purge=true` that also sweeps the
SET-NULL tables (steps 3–5) in one transaction — remains on the
backlog. Until then, steps 3–5 are manual.

---

## When to add new sources to this runbook

Any new table that links to `mailbox_id` (directly or via
`message_id`) is a candidate for inclusion. When adding such a
table:

1. Add the migration as usual.
2. Add the table to the inventory in **Scope** above.
3. Add a Step-3 JSON-export block.
4. Update the **Right-to-be-forgotten** purge sequence.

Keeping the runbook in lockstep with the schema is part of the
acceptance criteria for any privacy-relevant migration.
