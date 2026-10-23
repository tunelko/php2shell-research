# PHP challenge platform. This service uses patched PHP; the vulnerable PHP
# 8.4.26 runtime is the separate `vulnerable` service.
ARG BASE_IMAGE=php:8.4.27-apache@sha256:a0b75cee7023ba2c127138dcad2ecc6ec7e09435534645e70450f29f24ea2a5a
FROM ${BASE_IMAGE}

ENV PUBLIC_TARGET_ORIGIN=http://127.0.0.1:8426 \
    INTERNAL_VULNERABLE_URL=http://vulnerable/version.php \
    INTERNAL_PATCHED_URL=http://patched/version.php

COPY challenge/platform/public/ /var/www/html/
COPY solver/solve_remote.py /tmp/player/solve_remote.py
COPY solver/bootstrap_upstream.py /tmp/player/bootstrap_upstream.py
COPY solver/request_display_patch.py /tmp/player/request_display_patch.py
COPY solver/profiles/ /tmp/player/profiles/
COPY solver/PLAYER.md /tmp/player/README.md

RUN set -eux; \
    a2enmod rewrite; \
    mkdir -p /var/www/html/download; \
    tar -czf /var/www/html/download/player-bundle.tar.gz -C /tmp/player .; \
    chown -R www-data:www-data /var/www/html; \
    find /var/www/html -type d -exec chmod 0750 {} +; \
    find /var/www/html -type f -exec chmod 0440 {} +; \
    rm -rf /tmp/player

EXPOSE 80

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
  CMD ["php", "-r", "exit(str_contains((string)@file_get_contents('http://127.0.0.1/healthz'), 'ok') ? 0 : 1);"]
