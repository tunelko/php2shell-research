# PHP2Shell challenge platform

This container is a PHP/Apache distribution and monitoring surface for the
challenge. It runs patched PHP 8.4.27; the intentionally vulnerable PHP 8.4.26
runtime is the separate `vulnerable` service. It does not mount the Docker
socket.

It provides:

- an English landing page;
- challenge metadata at `/api/challenge`;
- live vulnerable/patched fingerprints at `/api/status`;
- a Docker-free player bundle at `/download/player-bundle.tar.gz`;
- a health endpoint at `/healthz`.

The player bundle contains:

```text
solve_remote.py
bootstrap_upstream.py
README.md
```

The platform front controller is `challenge/challenge/platform/public/index.php`.

`README.md` is the player-facing `exploit/PLAYER.md` document, not the larger
organizer guide.

The exploit core is not vendored. `bootstrap_upstream.py` fetches and checks out
the pinned public research commit when the player runs the solver.

