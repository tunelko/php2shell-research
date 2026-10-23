# Solver and profiles

`solve_remote.py` is the player-facing runner. `solve_local.py` is the
organizer-only fixed-proof verifier.

The remote runner detects PHP from `X-Powered-By`, selects an exact calibrated
profile, pins the public research exploit, obtains both randomized bases at run
time, executes the fixed proof, and writes an auditable ASLR report.

```sh
./solver/solve_remote.py http://127.0.0.1:8426
```

Ship the player bundle as:

```text
solver/solve_remote.py
solver/bootstrap_upstream.py
solver/request_display_patch.py
solver/profiles/
solver/PLAYER.md
```

`bootstrap_upstream.py` clones and checks out the public research exploit.
`request_display_patch.py` adds optional live request output. Neither the
upstream source nor a modified fork of it is redistributed.

Profiles are selected only when `verified` and `rce` are both true. Offsets and
heap geometry are tied to exact PHP version, architecture, distribution and
image build.
