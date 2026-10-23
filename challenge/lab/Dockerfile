ARG BASE_IMAGE=php:8.4.26-apache
FROM ${BASE_IMAGE}

ARG ROLE=vulnerable

RUN set -eux; \
    if [ "$ROLE" != "vulnerable" ] && [ "$ROLE" != "patched" ]; then \
      echo "ROLE must be vulnerable or patched" >&2; \
      exit 1; \
    fi; \
    mkdir -p /out; \
    chown www-data:www-data /out; \
    chmod 0750 /out; \
    mkdir -p /var/www/html/proof; \
    chown www-data:www-data /var/www/html/proof; \
    chmod 0750 /var/www/html/proof; \
    ln -s /var/www/html/proof/p /p; \
    printf '%s\n' \
      '#!/bin/sh' \
      'set -eu' \
      'dir=/var/www/html/proof' \
      'token=$(od -An -N16 -tx1 /dev/urandom | tr -d " \n")' \
      'shell="$dir/shell-$token.php"' \
      'sed "s/__P2S_TOKEN__/$token/g" /opt/php2shell/shell.php > "$shell"' \
      'chmod 0444 "$shell"' \
      'printf '\''{"path":"/proof/shell-%s.php","token":"%s"}'\'' "$token" "$token" > /p' \
      > /s; \
    chmod 0755 /s; \
    printf '%s\n' 'PHP2SHELL{ASLR_is_not_a_boundary}' > /flag; \
    chmod 0444 /flag

COPY php2shell.ini /usr/local/etc/php/conf.d/zz-php2shell.ini
COPY apache/php2shell.conf /etc/apache2/conf-enabled/zz-php2shell.conf
COPY html/ /var/www/html/
COPY shell.php /opt/php2shell/shell.php

RUN set -eux; \
    apache2ctl configtest

LABEL org.opencontainers.image.title="PHP2Shell ASLR challenge lab" \
      org.opencontainers.image.description="Isolated Apache mod_php lab for CVE-2026-109618 and CVE-2026-109619" \
      org.opencontainers.image.licenses="MIT" \
      php2shell.role="${ROLE}" \
      php2shell.php-version="${PHP_VERSION}"

EXPOSE 80

