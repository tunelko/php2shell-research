# Research tooling

This repository keeps the player-facing challenge and the organizer research
factory separate. Players need only `solve_remote.py`, `bootstrap_upstream.py`
and the verified JSON profiles. Organizers can use the additional tools below.

## Inventory

```sh
make inventory
./research/profile_inventory.py --enabled
./research/profile_inventory.py --check
```

The inventory enforces:

- one profile per PHP version, architecture and distribution;
- `verified` and `rce` agreement;
- complete leak/offset/heap data for every enabled profile;
- no accidental `htdata` claim in an unverified profile.

Generated table:

```text
solver/profiles/INVENTORY.md
```

## Offset extraction

Extract `zif_system` and `zval_ptr_dtor` without running an exploit:

```sh
make extract-offsets IMAGE=php:8.4.26-apache PLATFORM=linux/amd64
./research/extract_offsets.py --image php:8.5.11-apache --platform linux/arm64
```

The tool starts a disposable Docker container, copies `libphp.so`, parses its
ELF symbol table, and records the image identity and library SHA-256. It does
not calibrate the heap stages and does not claim RCE.

## Calibration factory

Calibrate one image:

```sh
./research/calibrate_image.py --image php:8.5.11-apache --platform linux/amd64
```

Named matrices:

```sh
./research/matrix_runner.py --set verified --list
./research/matrix_runner.py --set verified --refresh
./research/matrix_runner.py --set branches --refresh
./research/matrix_runner.py --set historical --list
./research/matrix_runner.py --set full --refresh
```

Equivalent Make targets:

```sh
make matrix MATRIX=verified
make matrix-refresh MATRIX=verified
make matrix-full
```

The runner records one JSON/Markdown report and a log for every attempt. It
retries probabilistic entries and refuses to replace an existing verified RCE
profile with a failed rerun unless `--force` is explicitly supplied. `full` is
intentionally expensive: it includes verified builds, representative branches,
and historical aarch64 targets. Inspect it with `--list` or `--dry-run` before
running Docker.

## Exact request dumps

During a real authorized run:

```sh
./solver/solve_remote.py http://127.0.0.1:8426 \
  --dump-requests out/request-dumps
```

Each exchange is archived with exact request bytes, response bytes, sizes and
SHA-256 hashes. See `request-dumps.md`.

## Remote assessment

The player runner has a non-exploiting assessment mode:

```sh
./solver/solve_remote.py http://127.0.0.1:8426 --dry-run
```

It resolves `X-Powered-By`, selects the exact architecture profile, and prints
the offsets without fetching the public exploit or sending the corruption chain.

## Tests and CI

```sh
python3 -m py_compile exploit/*.py
python3 -m unittest discover -s tests -v
./research/profile_inventory.py --check
./research/matrix_runner.py --set full --dry-run
```

GitHub workflow:

```text
.github/workflows/ci.yml
```

It tests Python 3.11–3.13, validates profile consistency, compiles all research
tools, and checks the full matrix shape. Docker exploitation is intentionally
not run in hosted CI.
