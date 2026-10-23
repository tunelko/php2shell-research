# PHP2Shell challenge architecture

## Components

```text
player
  |
  | HTTP only
  v
vulnerable PHP/Apache worker
  |
  | proof or token-protected shell endpoint
  v
player runner

organizer
  |
  | Docker, local only
  v
calibrator / local verifier
```

### Vulnerable target

The vulnerable target uses Apache `mod_php`, not PHP-FPM:

```text
Apache parent process
  └── one prefork worker
        └── libphp.so
```

This distinction is important. Successful exploitation can abort or segfault the
worker while the Apache parent creates a replacement. The container and service
therefore remain alive even though PHP's request state is corrupted.

### Patched control

PHP 8.4.27 runs with the same application and matching configuration. A
version-aware runner or calibrator must reject it.

### Platform

The platform is a PHP/Apache service running patched PHP 8.4.27. It:

- serves English documentation;
- probes the two PHP services through the internal Compose network;
- builds a player bundle;
- provides a health endpoint.

It does not mount `/var/run/docker.sock`, read `/flag`, or execute commands.

## Exploit data flow

### Stage 1: heap disclosure

A crafted multipart request drives PHP into the vulnerable OOM/stale-state path.
A following request causes response data to include heap pointers. The runner
derives the most frequent 2 MiB-aligned candidate as the Zend MM chunk base.

### Stage 2: `libphp.so` disclosure

A second stale-state shape causes a pointer to `zval_ptr_dtor` to appear in the
response. The runner subtracts the build-relative symbol offset:

```text
libphp_base = leaked_zval_ptr_dtor_pointer - zval_ptr_dtor_offset
```

### Stage 3: derived control flow

The two leaked bases and two constant offsets are combined:

```text
HTDATA     = zend_chunk_base + HTDATA_OFFSET
zif_system = libphp_base     + ZIF_SYSTEM_OFFSET
```

The forged object uses these runtime-derived addresses. This is why the chain
works with ASLR enabled.

## Worker lifecycle

The chain is intentionally disruptive. Typical Apache logs include:

```text
zend_mm_heap corrupted
Apache child exit signal Abort (6)
Apache child exit signal Segmentation fault (11)
```

The Apache parent starts a replacement worker. This is not simulation: logs and
process IDs show real worker recycling.

## Remote shell

The shell mode uses a staged bridge rather than binding a new network listener.

1. The stage-3 carrier executes `/s`.
2. `/s` copies a PHP template into the webroot with a random 128-bit token.
3. A one-time descriptor is written to `/proof/p`.
4. The runner obtains the descriptor and the endpoint deletes it after the first
   authenticated use.
5. The shell endpoint validates `X-P2S-Token`.
6. Commands are submitted as JSON and executed through `proc_open`.
7. stdout, stderr, exit code, and working directory are returned as JSON.

This avoids exposing a pre-existing webshell and avoids reverse-shell
connections from the challenge network.

## Calibration model

Different PHP images vary in:

- symbol offsets inside `libphp.so`;
- extension layout;
- allocator behavior;
- multipart heap shape;
- stage-1 carrier length;
- stage-2 array index;
- stage-3 live-object offset.

The calibrator starts a disposable local replica, extracts the ELF symbols,
calibrates stages 1 and 2, tries known stage-3 layouts, and writes:

```text
solver/profiles/<php-version>-<arch>-<distro>.json
```

The profile records:

- image digest;
- PHP version;
- architecture and distribution;
- `libphp.so` SHA-256;
- symbol offsets;
- heap parameters;
- measured runtime bases;
- whether the fixed `id` proof succeeded.

No profile is marked `rce=true` without a real proof.

## Deployment boundaries

| Interface | Default | Intended audience |
|---|---|---|
| Platform HTTP | `127.0.0.1:8080` | organizer and players |
| Vulnerable HTTP | `127.0.0.1:8426` | organizer, then controlled CTF network |
| Patched HTTP | `127.0.0.1:8427` | organizer |
| Docker socket | not exposed to containers | organizer host only |

## Security invariants

- Player code does not require Docker.
- The platform does not require Docker.
- The shell endpoint does not exist before exploitation.
- The remote runner has no arbitrary command flag.
- The local calibrator has no arbitrary command flag.
- Fixed PHP versions are rejected.
- The upstream exploit commit is pinned and checked out explicitly.
- Public exposure is expected to be controlled by a firewall or VPN.
