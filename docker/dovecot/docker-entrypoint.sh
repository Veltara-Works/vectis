#!/bin/sh
set -e

# Ensure proper ownership of mail directory (top-level only, -R would be slow on large trees)
chown vmail:vmail /var/vectis/mail

# Fix permissions on SQL config (contains password)
chmod 640 /etc/dovecot/dovecot-sql.conf.ext 2>/dev/null || true

exec "$@"
