#!/usr/bin/env python3
"""Extract libphp symbol offsets from a local PHP Apache Docker image."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

from calibrate_image import (
    LIBPHP_PATHS,
    image_arch,
    image_digest,
    parse_libphp_symbols,
    pull_if_needed,
)


def docker_run(image: str, platform: str | None, args: list[str]) -> bytes:
    command = ["docker", "run", "--rm"]
    if platform:
        command += ["--platform", platform]
    command += [image, *args]
    result = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"docker run failed ({result.returncode}): {result.stderr.decode('utf-8', 'replace').strip()}"
        )
    return result.stdout


def find_libphp(image: str, platform: str | None) -> str:
    probe = "for p in " + " ".join(LIBPHP_PATHS) + "; do [ -f \"$p\" ] && printf %s \"$p\" && exit 0; done; exit 1"
    path = docker_run(image, platform, ["sh", "-c", probe]).decode("utf-8", "replace").strip()
    if not path:
        raise RuntimeError(f"no known libphp.so path found in {image}")
    return path


def extract(image: str, platform: str | None) -> dict[str, str]:
    pull_if_needed(image, platform)
    architecture = image_arch(image)
    expected = {"linux/amd64": "amd64", "linux/arm64": "aarch64"}.get(platform)
    if expected and architecture != expected:
        raise RuntimeError(f"requested {platform} but image resolved to {architecture}")

    libphp_path = find_libphp(image, platform)
    with tempfile.TemporaryDirectory(prefix="p2s-libphp-") as temporary:
        destination = Path(temporary) / "libphp.so"
        blob = docker_run(image, platform, ["cat", libphp_path])
        destination.write_bytes(blob)
        _bias, symbols = parse_libphp_symbols(destination)
        digest = hashlib.sha256(blob).hexdigest()

    php_version = docker_run(
        image,
        platform,
        ["php", "-r", "echo PHP_VERSION;"],
    ).decode("ascii", "replace").strip()
    return {
        "image": image,
        "image_digest": image_digest(image),
        "php_version": php_version,
        "arch": architecture,
        "sapi": "apache2handler",
        "libphp_path": libphp_path,
        "libphp_sha256": digest,
        "libphp": {
            "zif_system": f"0x{symbols['zif_system']:x}",
            "zval_ptr_dtor": f"0x{symbols['zval_ptr_dtor']:x}",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, help="PHP Apache image, for example php:8.4.26-apache")
    parser.add_argument("--platform", help="Docker platform, for example linux/arm64")
    parser.add_argument("--output", type=Path, help="write JSON here instead of stdout")
    args = parser.parse_args()

    try:
        result = extract(args.image, args.platform)
    except (OSError, RuntimeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    rendered = json.dumps(result, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        print(f"[+] offsets written: {args.output}")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
