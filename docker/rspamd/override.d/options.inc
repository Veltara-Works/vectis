# Vectis Mail: resolve through the bundled unbound on 127.0.0.1 (ADR-026,
# #258) so blocklist lookups come from this host's own IP. The entrypoint
# removes this file when VECTIS_RSPAMD_LOCAL_RESOLVER=false, leaving rspamd
# on the container's default resolver. The other values restate rspamd's
# stock options.inc dns settings, so they survive this override.
dns {
    nameserver = ["127.0.0.1:53"];
    timeout = 1.0;
    sockets = 16;
    retransmits = 5;
}
