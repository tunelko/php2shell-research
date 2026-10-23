# PHP2Shell player runner

## Requirements

- Python 3.11 or newer
- Git
- Outbound HTTPS access to GitHub
- HTTP access to the authorized challenge target

Docker is not required.

## Fixed proof

```sh
./solve_remote.py http://challenge-host:8426
```

The runner:

1. detects PHP from `X-Powered-By`;
2. selects the matching calibrated architecture profile;
3. fetches and pins the public research exploit;
4. leaks the Zend heap base;
5. leaks the `libphp.so` base;
6. derives `HTDATA` and `zif_system`;
7. executes only `cat /flag >/p`;
8. writes `php2shell-aslr-report.json`.

If the version header is hidden:

```sh
./solve_remote.py http://challenge-host:8426 --version 8.4.26
```

If a version has multiple architecture profiles:

```sh
./solve_remote.py http://challenge-host:8426 \
  --version 8.5.11 --arch amd64
```

Without a usable version:

```text
ERROR: version no detectada, requiere --version
```

## Interactive shell

```sh
./solve_remote.py http://challenge-host:8426 --shell
```

Optional pwntools frontend:

```sh
./solve_remote.py http://challenge-host:8426 \
  --shell --pwn-interactive
```

## Real request output

```sh
./solve_remote.py http://challenge-host:8426 --show-requests
```

Show and archive exact request/response bytes:

```sh
./solve_remote.py http://challenge-host:8426 \
  --dump-requests request-dumps
```

## Options

```text
--timeout SECONDS   Per-request timeout; default 60
--retries COUNT     Leak-stage retries; default 3
--version VERSION   Force a calibrated PHP version
--arch ARCH         Select amd64 or aarch64 when needed
--show-requests     Show real exchanges live
--dump-requests DIR Show and archive exact exchanges
--report PATH       ASLR report output path
--pwn-interactive   Use pwntools with --shell
```

There is no arbitrary-command option.

The player bundle contains:

```text
solve_remote.py
bootstrap_upstream.py
request_display_patch.py
profiles/
README.md
```
