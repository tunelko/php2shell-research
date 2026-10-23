# Runtime changes applied to the public exploit

The core primitive remains the public repository created by **9bie and
contributors**:

```text
https://github.com/9bie/php2shell-bypass-aslr-exp
commit 4586f5cc120c82fd468b17469202bac629810ad9
```

`solver/bootstrap_upstream.py` does not redistribute a fork. It clones or
checks out that commit and applies two narrow in-place changes.

## 1. Neutral upload-progress field

The challenge uses:

```ini
session.upload_progress.name = "progress_meter_challenge_id"
```

Its length matches PHP's 27-byte default field, preserving heap geometry while
avoiding WAF rules that reject the default name.

## 2. Profile-driven heap geometry

After the upstream constructor chooses its built-in profile, the bootstrap adds
environment overrides:

```text
P2S_STAGE1_N
P2S_STAGE1_FORGE_LEN
P2S_STAGE2_T
P2S_STAGE2_V
P2S_STAGE3_STYLE
```

`solve_remote.py` supplies these values from the selected JSON profile. This is
what allows the same pinned primitive to run builds such as PHP 8.4.26 amd64
and PHP 8.5.11 aarch64 without maintaining a modified exploit fork.

The upstream repository has no explicit license, so the modified source is not
copied into this repository or redistributed. `git diff` inside
`solver/vendor/php2shell-upstream` shows the runtime changes after bootstrap.

## 3. Exact request dumps

`patch_request_dump()` adds an optional wire-archive hook controlled by:

```text
P2S_REQUEST_DUMP_DIR
```

When `solve_remote.py --dump-requests DIR` sets it, every `Target.post()` and
`Target.get()` exchange is archived as exact gzip-compressed application bytes
plus JSON metadata and SHA-256 hashes. Dumping is disabled by default.
