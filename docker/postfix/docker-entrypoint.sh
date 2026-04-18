#!/bin/sh
set -e

# Ensure proper ownership of mail directory (top-level only)
chown vmail:vmail /var/vectis/mail

# Ensure /var/log/postfix exists and is writable by postfix (shared volume
# may have been created empty by Docker with root ownership).
mkdir -p /var/log/postfix
chown postfix:postfix /var/log/postfix
touch /var/log/postfix/mail.log
chown postfix:postfix /var/log/postfix/mail.log

# Fix permissions on SQL lookup files (contain passwords)
if [ -d /etc/postfix ]; then
    chmod 640 /etc/postfix/pgsql_*.cf 2>/dev/null || true
fi

# Mirror the Postfix log file to stdout so `docker logs vectis-postfix`
# keeps showing mail activity, while the API container tails the same
# file via the shared postfix-logs volume for delivery/bounce webhooks.
tail -n 0 -F /var/log/postfix/mail.log &

exec "$@"
