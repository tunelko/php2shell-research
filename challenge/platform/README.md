# PHP2Shell challenge platform

This service is a PHP/Apache distribution and monitoring surface for the local
challenge. It runs patched PHP 8.4.27; the intentionally vulnerable PHP 8.4.26
runtime is the separate `vulnerable` service. It does not mount the Docker
socket.

Endpoints:

```text
/                           landing page
/healthz                    service health
/api/challenge              challenge metadata
/api/status                 vulnerable/patched fingerprints
/download/player-bundle.tar.gz
```

The player bundle contains:

```text
solve_remote.py
bootstrap_upstream.py
request_display_patch.py
profiles/
README.md
```

The bundled `README.md` is the player-facing `solver/PLAYER.md` document. The
exploit core is not vendored; `bootstrap_upstream.py` fetches and checks out the
pinned public research commit when the player runs the solver.

Build through `challenge/compose/platform.yml` from the repository root.
