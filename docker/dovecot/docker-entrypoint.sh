#!/bin/sh
set -e

# Ensure proper ownership of mail directory (top-level only, -R would be slow on large trees)
chown vmail:vmail /var/vectis/mail

# Fix permissions on SQL config (contains password)
chmod 640 /etc/dovecot/dovecot-sql.conf.ext 2>/dev/null || true

# Pre-compile the global "before" Sieve script. Dovecot 2.4 requires global Sieve
# scripts to be pre-compiled: at delivery the LDA runs as vmail and the script is
# bind-mounted read-only, so it cannot write the .svbin itself (2.4 logs a
# permission error and recompiles on every delivery otherwise). sievec runs here
# as root and writes the .svbin into the root-owned sieve dir; vmail reads it.
if [ -f /etc/dovecot/sieve/spam-to-junk.sieve ]; then
    sievec /etc/dovecot/sieve/spam-to-junk.sieve 2>/dev/null || \
        echo "warning: sievec pre-compile of spam-to-junk.sieve failed; will compile at delivery" >&2
fi

exec "$@"
