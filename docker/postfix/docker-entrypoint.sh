#!/bin/sh
set -e

# Ensure proper ownership of mail directory (top-level only)
chown vmail:vmail /var/vectis/mail

# Fix permissions on SQL lookup files (contain passwords)
if [ -d /etc/postfix ]; then
    chmod 640 /etc/postfix/pgsql_*.cf 2>/dev/null || true
fi

exec "$@"
