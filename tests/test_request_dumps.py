import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "solver"))
sys.path.insert(0, str(ROOT / "research"))

from bootstrap_upstream import patch_request_dump
from request_display_patch import patch_request_display


MINIMAL_SOURCE = '''#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os


class Target:
    def __init__(self, url: str, timeout: float = 30.0, verbose: bool = True):
        self.host = url
        self.port = 80
        self.path = "/index.php"
        self.timeout = timeout
        self.verbose = verbose

    def post(self, body: bytes, boundary: bytes, read_cap: int = 1 << 20,
             timeout: float | None = None,
             extra_headers: dict[str, str] | None = None) -> bytes:
        hdr = b"POST /index.php HTTP/1.1\\r\\n\\r\\n"
        data = bytearray(b"response")
        reader = threading.Thread(target=lambda: None)
        try:
            reader.join(timeout=(timeout or self.timeout) + 1.0)
            return bytes(data)
        finally:
            pass

    def get(self, path: str, read_cap: int = 1 << 20) -> tuple[int, bytes]:
        hdr = b"GET /proof/p HTTP/1.1\\r\\n\\r\\n"
        data = bytearray(b"response")
        head, _, body = bytes(data).partition(b"\\r\\n\\r\\n")
        m = re.match(rb"HTTP/1\\.[01] (\\d{3})", head)
        return (int(m.group(1)) if m else 0), body
'''


class RequestDumpPatchTests(unittest.TestCase):
    def test_patch_adds_exact_exchange_archive(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            path = repo / "exploit.py"
            path.write_text(MINIMAL_SOURCE, encoding="utf-8")
            patch_request_dump(repo)
            source = path.read_text(encoding="utf-8")

            self.assertIn("P2S_REQUEST_DUMP_DIR", source)
            self.assertIn("def _dump_exchange", source)
            self.assertIn('self._dump_exchange("POST", hdr, body, result)', source)
            self.assertIn('self._dump_exchange("GET", hdr, b"", bytes(data))', source)
            self.assertIn('prefix + ".request.gz"', source)
            self.assertIn('hashlib.sha256(request).hexdigest()', source)
            compile(source, str(path), "exec")

    def test_patch_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repo = Path(temporary)
            path = repo / "exploit.py"
            path.write_text(MINIMAL_SOURCE, encoding="utf-8")
            patch_request_dump(repo)
            patch_request_display(repo)
            first = path.read_text(encoding="utf-8")
            patch_request_dump(repo)
            patch_request_display(repo)
            self.assertEqual(path.read_text(encoding="utf-8"), first)


if __name__ == "__main__":
    unittest.main()
