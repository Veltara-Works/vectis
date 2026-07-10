# Pinned to an exact upstream version (P2-M5) — `:latest-apache` would let a
# Roundcube release silently change the webmail on the next image rebuild.
# Bump deliberately after testing the new version's skin/config compatibility.
FROM roundcube/roundcubemail:1.7.2-apache

# Security patch layer (audit): the pinned upstream base ships an ImageMagick
# vulnerable to CVE-2026-56367 (CRITICAL), fixed in the Debian 13 archive as
# imagemagick 8:7.1.1.43+dfsg1-1+deb13u11. Because the base tag is pinned
# deliberately, a rebuild alone won't pull the fix — so we upgrade the installed
# magick packages in-place. This FIXES rather than suppresses (see .trivyignore
# policy); drop this layer once the base republishes with the patched package.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends --only-upgrade \
      $(dpkg-query -W -f='${Package}\n' 'imagemagick*' 'libmagick*' 2>/dev/null); \
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
