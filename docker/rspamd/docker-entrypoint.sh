#!/bin/sh
set -e

# Ensure DKIM keys directory is readable
chmod -R 644 /var/vectis/dkim/*.key 2>/dev/null || true

exec "$@"
