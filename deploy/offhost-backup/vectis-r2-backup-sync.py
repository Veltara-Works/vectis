#!/usr/bin/env python3
"""Off-host backup sync: push encrypted Vectis backup archives to Cloudflare R2.

Interim durability measure that closes the single-host SPOF (backups otherwise
live only on this VPS) until the in-app S3 uploader ships as a product feature.

Only *.tar.gz.enc archives are uploaded — these are AES-256-GCM encrypted and
exclude secrets.yaml, so they are safe to hold off-host. The unencrypted
pre-*.sql.gz cutover dumps in the same directory are deliberately NOT synced.

Credentials + target come from the environment (see the accompanying systemd
unit's EnvironmentFile=/etc/vectis/r2-backup.env):

    R2_ENDPOINT             https://<accountid>.r2.cloudflarestorage.com
    R2_BUCKET               vectis-mail-backups
    AWS_ACCESS_KEY_ID       R2 access key id (bucket-scoped token)
    AWS_SECRET_ACCESS_KEY   R2 secret access key

The sync is idempotent (uploads only archives not already in the bucket) and
never deletes from R2 — object expiry is handled by the bucket lifecycle rule.
Use --dry-run to print the plan without uploading.
"""
import argparse
import glob
import os
import sys

import boto3
from botocore.config import Config

BACKUP_DIR = os.environ.get("VECTIS_BACKUP_DIR", "/var/vectis/backups")
ARCHIVE_GLOB = "*.tar.gz.enc"


def main() -> int:
    ap = argparse.ArgumentParser(description="Sync Vectis encrypted backups to R2.")
    ap.add_argument("--dry-run", action="store_true",
                    help="list what would be uploaded without uploading")
    args = ap.parse_args()

    endpoint = os.environ.get("R2_ENDPOINT", "")
    bucket = os.environ.get("R2_BUCKET", "")
    missing = [k for k, v in (("R2_ENDPOINT", endpoint), ("R2_BUCKET", bucket)) if not v]
    if missing:
        print(f"missing required env var(s): {', '.join(missing)}", file=sys.stderr)
        return 2
    if not endpoint.startswith("https://"):
        # Refuse plaintext endpoints — credentials must never go over http://.
        print(f"R2_ENDPOINT must be an https:// URL (got {endpoint!r})", file=sys.stderr)
        return 2

    s3 = boto3.client(
        "s3", endpoint_url=endpoint, region_name="auto",
        config=Config(signature_version="s3v4", retries={"max_attempts": 3}),
    )

    local = sorted(glob.glob(os.path.join(BACKUP_DIR, ARCHIVE_GLOB)))
    if not local:
        print(f"no {ARCHIVE_GLOB} archives in {BACKUP_DIR}; nothing to do")
        return 0

    existing = set()
    paginator = s3.get_paginator("list_objects_v2")
    for page in paginator.paginate(Bucket=bucket):
        for obj in page.get("Contents", []):
            existing.add(obj["Key"])

    uploaded = skipped = failed = 0
    for path in local:
        key = os.path.basename(path)
        if key in existing:
            skipped += 1
            continue
        size = os.path.getsize(path)
        if args.dry_run:
            print(f"WOULD UPLOAD {key} ({size} bytes)")
            uploaded += 1
            continue
        try:
            s3.upload_file(path, bucket, key)
            print(f"uploaded {key} ({size} bytes)")
            uploaded += 1
        except Exception as e:  # noqa: BLE001 - log + continue, don't abort the batch
            print(f"FAILED {key}: {e}", file=sys.stderr)
            failed += 1

    verb = "to upload" if args.dry_run else "uploaded"
    print(f"done: {uploaded} {verb}, {skipped} already present, "
          f"{failed} failed, {len(existing)} currently in bucket")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
