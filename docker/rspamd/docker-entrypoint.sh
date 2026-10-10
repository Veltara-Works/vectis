#!/bin/sh
set -e

# Ensure DKIM keys directory is readable
chmod -R 644 /var/vectis/dkim/*.key 2>/dev/null || true

# Local recursive resolver for rspamd (ADR-026, #258). Blocklists refuse
# queries from shared/public resolvers, so rspamd resolves through unbound on
# 127.0.0.1 (override.d/options.inc). rspamd.local_resolver: false in
# config.yaml renders VECTIS_RSPAMD_LOCAL_RESOLVER=false, which skips it.
if [ "${VECTIS_RSPAMD_LOCAL_RESOLVER:-true}" = "false" ]; then
    rm -f /etc/rspamd/override.d/options.inc
    echo "[rspamd-entrypoint] local resolver disabled; using the container's default resolver"
else
    unbound-checkconf /etc/unbound/unbound.conf >/dev/null
    # Supervise: if unbound ever exits, restart it. This loop stays a child of
    # rspamd after the exec below and reaps its own unbound, so no zombies.
    # The healthcheck also queries unbound, so a resolver that keeps dying
    # still turns the container unhealthy.
    (
        while :; do
            unbound -d -c /etc/unbound/unbound.conf || true
            echo "[rspamd-entrypoint] unbound exited; restarting in 2s" >&2
            sleep 2
        done
    ) &
    # Don't let rspamd start scanning before its resolver answers: lookups
    # in that gap would fail and score nothing.
    i=0
    until nslookup health.vectis.internal 127.0.0.1 >/dev/null 2>&1; do
        i=$((i + 1))
        if [ "$i" -ge 60 ]; then
            echo "[rspamd-entrypoint] unbound did not answer within 30s" >&2
            exit 1
        fi
        sleep 0.5
    done
    echo "[rspamd-entrypoint] local resolver up on 127.0.0.1:53"
fi

exec "$@"
