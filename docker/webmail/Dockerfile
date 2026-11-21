# Pinned to an exact upstream version (P2-M5) — `:latest-apache` would let a
# Roundcube release silently change the webmail on the next image rebuild.
# Bump deliberately after testing the new version's skin/config compatibility.
FROM roundcube/roundcubemail:1.7.5-apache

# Security patch layer. The pinned upstream base lags the Debian 13 security
# archive (e.g. ImageMagick CVE-2026-56367, Brotli CVE-2026-111497, Apache
# mod_http2 CVE-2026-119618, glibc, libpq5, rsync, freetype, nghttp2), and a
# rebuild alone won't pull the fixes because the base tag is pinned
# deliberately. So every rebuild upgrades ALL installed packages in place
# (`apt-get upgrade` never adds or removes packages). This FIXES rather than
# suppresses (see .trivyignore policy). Before v0.1.65 this layer upgraded a
# hand-picked list, which let everything else go stale between base bumps.
#
# It also removes the C/C++ toolchain the base keeps from building its PHP
# extensions (gcc, g++, cpp, make, dpkg-dev and the -dev headers, including
# linux-libc-dev). Nothing uses it at runtime: PHP, Apache and Roundcube need
# none of it, and the purge was checked to leave libgcc-s1, libstdc++6 and
# libc6 installed. A public-facing webmail shouldn't carry a compiler, and the
# kernel headers alone were ~230 scanner findings for kernel code that can't
# run in a container (one CRITICAL, which failed the Trivy gate).
RUN set -eux; \
    apt-get update; \
    apt-get upgrade -y --no-install-recommends; \
    apt-get purge -y \
      gcc g++ cpp make dpkg-dev gcc-14 cpp-14 g++-14 libgcc-14-dev \
      gcc-14-x86-64-linux-gnu cpp-14-x86-64-linux-gnu \
      linux-libc-dev libc6-dev libc-dev-bin; \
    php -m >/dev/null; apache2ctl -t; \
    rm -rf /var/lib/apt/lists/*

# Bake the Vectis skin into /usr/src/. Roundcube's image entrypoint copies
# /usr/src/roundcubemail/. to /var/www/html on first start (and runs
# bin/installto.sh to update on later starts), so anything dropped here
# lands at /var/www/html/skins/vectis/ without needing a runtime mount.
# Skin is `extends: elastic` — the loader walks the inheritance chain so
# any template vectis doesn't define falls through to elastic.
COPY docker/webmail/skin/ /usr/src/roundcubemail/skins/vectis/
RUN chmod -R a+rX /usr/src/roundcubemail/skins/vectis

# Entrypoint task: append a one-liner to the upstream-generated
# config.docker.inc.php so it includes our per-install config overrides
# from config.vectis.inc.php (bind-mounted by the compose template).
# Runs after upstream's `*_create_docker_config.sh` thanks to the 99_
# numeric prefix → alphabetic ordering in /entrypoint-tasks/post-setup/.
COPY docker/webmail/99_vectis_include.sh /entrypoint-tasks/post-setup/99_vectis_include.sh
RUN chmod 0755 /entrypoint-tasks/post-setup/99_vectis_include.sh
