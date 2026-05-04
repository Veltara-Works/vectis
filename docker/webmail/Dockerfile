FROM roundcube/roundcubemail:latest-apache

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
