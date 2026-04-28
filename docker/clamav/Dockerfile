FROM alpine:3.21

# clamav          — base libs + freshclam (signature updater)
# clamav-daemon   — clamd binary
# clamav-clamdscan — used by HEALTHCHECK and sysadmin smoke test
# clamav-libunrar — RAR archive support (commonly used in mail attachments)
# bind-tools      — clamd reverse-DNS lookups + diagnostics
RUN apk add --no-cache \
    clamav \
    clamav-daemon \
    clamav-clamdscan \
    clamav-libunrar \
    ca-certificates \
    bind-tools

# Pre-populate the signature database during image build. ~1.5 GB download
# happens once at build time so a fresh container boots in seconds instead
# of waiting 5-10 minutes for the first freshclam run. The clamav-data
# volume preserves these across restarts; freshclam in the entrypoint keeps
# them current. The `|| true` survives transient mirror flakiness — a
# missing initial DB just means the first runtime freshclam has more to
# pull, not a broken image.
RUN mkdir -p /var/lib/clamav /var/log/clamav /var/run/clamav \
    && chown -R clamav:clamav /var/lib/clamav /var/log/clamav /var/run/clamav \
    && (su -s /bin/sh clamav -c "freshclam --no-warnings --quiet" || true)

# Signature database lives here. Bind to a named volume in compose so a
# container restart doesn't trigger a full re-download.
VOLUME ["/var/lib/clamav"]

# clamd TCP listener — rspamd connects here from vectis-mail.
EXPOSE 3310

COPY docker/clamav/docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# clamdscan --ping=N exits 0 when clamd PONGs within N seconds.
# start_period is generous (180s) because a freshly-mounted empty
# clamav-data volume forces an initial freshclam download before clamd
# can load the DB and start answering. Once warm, ping is sub-second.
HEALTHCHECK --interval=30s --timeout=15s --retries=3 --start-period=180s \
    CMD clamdscan --ping=1 || exit 1

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["clamd", "--foreground=yes"]
