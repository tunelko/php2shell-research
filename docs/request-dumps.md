# Exact request dumps

`--dump-requests` archives a byte-for-byte copy of every request actually sent
by the exploit. It also enables the live on-screen exchange summary:

```sh
./solver/solve_remote.py http://127.0.0.1:8426 \
  --dump-requests out/request-dumps \
  --report out/request-dump-report.json
```

Use only the live screen output when no files are needed:

```sh
./solver/solve_remote.py http://127.0.0.1:8426 --show-requests
```

`--dump-requests DIR` implies `--show-requests`. The given directory is a root;
each run creates a unique child such as:

```text
out/request-dumps/run-20261023T...-12345/
```

## Files per exchange

For every HTTP exchange sent by the pinned exploit:

```text
000001.json         metadata and SHA-256 hashes
000001.request.gz   exact bytes written on the wire: headers + multipart body
000001.response.gz exact response bytes observed by the client
```

The screen output prints the exact request headers, body size/hash, grouped
multipart fields, response headers and a response preview. It does not print
multi-megabyte repeated bodies.

The JSON metadata contains:

```text
method
request line
path
target
request/response filenames
request, header, body and response sizes
request, body and response SHA-256
```

Bodies are gzip-compressed because several exploit requests exceed 12 MiB.
Decompression restores the exact application byte stream. For HTTPS targets the
dump contains the plaintext HTTP stream before TLS encryption, not TLS records.

## Verify and inspect

```sh
# Verify that the archived request is byte-for-byte intact:
gzip -dc 000001.request.gz | sha256sum

# Compare with the metadata:
cat 000001.json

# Inspect the HTTP start and readable multipart fields:
gzip -dc 000001.request.gz | strings | head -80

# Inspect the exact response:
gzip -dc 000001.response.gz | head -40
```

The request archive begins with the real HTTP request line and headers:

```http
POST /index.php HTTP/1.1
Host: 127.0.0.1:8426
Content-Type: multipart/form-data; boundary=...
Content-Length: ...
Connection: close
```

## Scope and limitations

- Only requests made by the pinned exploit adapter are dumped.
- HTTPS dumps contain plaintext HTTP application bytes, not encrypted TLS frames.
- Initial wrapper fingerprint/header checks are not part of the dump.
- The remote shell bridge is not dumped by the exploit subprocess.
- A response is written after the exchange completes; a hard connection failure
  before `Target.post()` returns may not produce an archive.
- Dumps can be large and may contain the challenge flag or one-time shell token.
  Keep them inside the authorized laboratory.
