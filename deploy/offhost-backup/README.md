# Off-host backup sync (interim)

Pushes the encrypted Vectis backup archives (`/var/vectis/backups/*.tar.gz.enc`)
to a Cloudflare R2 bucket so a loss of the single VPS does not lose the backups.

This is an **interim ops measure** that closes the single-host SPOF. The
intended long-term solution is an in-app S3 uploader (hook the backup
scheduler's `SetOnComplete`) that ships as a configurable product feature; this
host-side timer can be removed once that lands.

## What is and isn't synced

- **Synced:** `*.tar.gz.enc` only — AES-256-GCM encrypted, exclude `secrets.yaml`.
  Safe to hold off-host (the decryption key stays on the host in `secrets.yaml`).
- **Not synced:** the unencrypted `pre-*.sql.gz` cutover dumps in the same dir,
  and `manifest.json`.

Uploads are idempotent (only archives missing from the bucket) and never delete
from R2 — expiry is handled by the bucket lifecycle rule (see below).

## Install (on the prod host, as root)

```sh
# 1. Credentials (root:root 0600). Values from the bucket-scoped R2 token.
install -m 0600 /dev/null /etc/vectis/r2-backup.env
cat > /etc/vectis/r2-backup.env <<'ENV'
R2_ENDPOINT=https://<accountid>.r2.cloudflarestorage.com
R2_BUCKET=vectis-mail-backups
AWS_ACCESS_KEY_ID=<r2-access-key-id>
AWS_SECRET_ACCESS_KEY=<r2-secret-access-key>
ENV

# 2. Script + units
install -m 0755 vectis-r2-backup-sync.py /usr/local/bin/vectis-r2-backup-sync.py
install -m 0644 vectis-r2-backup-sync.service /etc/systemd/system/
install -m 0644 vectis-r2-backup-sync.timer   /etc/systemd/system/

# 3. Enable
systemctl daemon-reload
systemctl enable --now vectis-r2-backup-sync.timer
```

Dependencies: `python3` + `boto3` (already present on the prod host).

## R2 bucket lifecycle (expire off-host copies ~35 days)

Slightly longer than the 30-day local retention so the off-host copy always
covers the local window. **Lifecycle is a bucket-admin operation — the
bucket-scoped sync token (object read+write only) cannot set it** (S3
`PutBucketLifecycleConfiguration` returns `AccessDenied`). Set it once via the
Cloudflare dashboard (R2 → bucket → Settings → Object lifecycle rules) or the
CF API with an admin/global credential. `maxAge` is in **seconds**
(`3024000` = 35 days); a PUT replaces the whole rule set, so keep the default
multipart-abort rule:

```
PUT /accounts/{account_id}/r2/buckets/vectis-mail-backups/lifecycle
{"rules":[
  {"id":"Default Multipart Abort Rule","enabled":true,"conditions":{},
   "abortMultipartUploadsTransition":{"condition":{"type":"Age","maxAge":604800}}},
  {"id":"expire-offhost-backups-35d","enabled":true,"conditions":{"prefix":""},
   "deleteObjectsTransition":{"condition":{"type":"Age","maxAge":3024000}}}
]}
```

## Verify

```sh
python3 /usr/local/bin/vectis-r2-backup-sync.py --dry-run   # plan only
systemctl start vectis-r2-backup-sync.service               # run once now
journalctl -u vectis-r2-backup-sync.service --no-pager | tail
systemctl list-timers vectis-r2-backup-sync.timer
```
