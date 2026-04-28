#!/bin/sh
# Vectis ClamAV container entrypoint
#
# Responsibilities:
#   1. Ensure runtime dirs exist + are owned by `clamav` (handles fresh
#      named-volume mounts where /var/lib/clamav is empty + root-owned).
#   2. If signature DB is missing, run a one-shot freshclam to seed it.
#   3. Start freshclam in --daemon mode for periodic refresh.
#   4. Exec clamd in the foreground as the main process.
#
# Logs to stderr/stdout — captured by the configured Docker log driver.

set -e

mkdir -p /var/lib/clamav /var/log/clamav /var/run/clamav
chown -R clamav:clamav /var/lib/clamav /var/log/clamav /var/run/clamav

# Initial signature population if volume is empty. ClamAV accepts either
# .cvd (compressed) or .cld (incremental) signature files for `main`.
if [ ! -f /var/lib/clamav/main.cvd ] && [ ! -f /var/lib/clamav/main.cld ]; then
    echo "[clamav-entrypoint] No signatures present; running initial freshclam..."
    if ! su -s /bin/sh clamav -c "freshclam --no-warnings"; then
        echo "[clamav-entrypoint] WARN: initial freshclam failed; clamd will retry on schedule" >&2
    fi
fi

# Periodic signature refresh (every 2h ≈ 12 checks/day, the freshclam
# default). Daemon mode forks; we discard its pid because clamd exit
# is what controls container lifetime.
echo "[clamav-entrypoint] Starting freshclam in daemon mode..."
su -s /bin/sh clamav -c "freshclam --daemon --no-warnings --checks=12" &

echo "[clamav-entrypoint] Starting clamd..."
exec "$@"
