#!/usr/bin/env python3
"""Patch the pinned primitive to print real exchanges while they happen."""

from __future__ import annotations

from pathlib import Path


OLD = '''    def _dump_exchange(self, method: str, headers: bytes, body: bytes,
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
        request_line = headers.split(b"\\r\\n", 1)[0].decode("ascii", "replace")
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
            fh.write("\\n")
'''

NEW = r'''    @staticmethod
    def _preview(data: bytes, limit: int = 96) -> str:
        return repr(data[:limit])

    @staticmethod
    def _group_name(name: str) -> str:
        return re.sub(r"\d+", "#", name)

    def _multipart_summary(self, body: bytes, boundary: bytes) -> list[str]:
        marker = b"--" + boundary
        positions: list[int] = []
        cursor = body.find(marker)
        while cursor >= 0:
            positions.append(cursor)
            cursor = body.find(marker, cursor + len(marker))
        if len(positions) < 2:
            return [f"body preview: {self._preview(body)}"]

        groups: dict[tuple[str, str | None], dict[str, object]] = {}
        for start, end in zip(positions, positions[1:]):
            segment = body[start + len(marker):end].lstrip(b"\r\n")
            if segment.startswith(b"--"):
                continue
            head, separator, payload = segment.partition(b"\r\n\r\n")
            if not separator:
                continue
            if payload.endswith(b"\r\n"):
                payload = payload[:-2]
            match = re.search(
                rb'Content-Disposition: form-data; name="([^"]+)"(?:; filename="([^"]+)")?',
                head,
            )
            if not match:
                continue
            name = match.group(1).decode("utf-8", "replace")
            filename = (
                match.group(2).decode("utf-8", "replace")
                if match.group(2) is not None else None
            )
            key = (self._group_name(name), filename)
            group = groups.setdefault(key, {
                "count": 0, "bytes": 0, "preview": self._preview(payload, 24),
            })
            group["count"] = int(group["count"]) + 1
            group["bytes"] = int(group["bytes"]) + len(payload)

        lines: list[str] = []
        for (name, filename), group in groups.items():
            disposition = name if filename is None else f'{name}; filename="{filename}"'
            lines.append(
                f"      {disposition}: count={group['count']} "
                f"bytes={group['bytes']} preview={group['preview']}"
            )
        return lines

    def _print_exchange(self, sequence: int, headers: bytes, body: bytes,
                        boundary: bytes | None, response: bytes,
                        request_path: str | None, response_path: str | None) -> None:
        request_line = headers.split(b"\r\n", 1)[0].decode("ascii", "replace")
        print(f"\n[REAL REQUEST {sequence:06d}]", flush=True)
        print(headers.decode("latin1", "replace"), end="", flush=True)
        print(f"      body-bytes={len(body)} body-sha256={hashlib.sha256(body).hexdigest()}", flush=True)
        if boundary is not None:
            print(f"      multipart-summary boundary={boundary.decode('latin1', 'replace')}", flush=True)
            for line in self._multipart_summary(body, boundary):
                print(line, flush=True)
        elif body:
            print(f"      body-preview={self._preview(body)}", flush=True)

        response_head, separator, response_body = response.partition(b"\r\n\r\n")
        print(f"[REAL RESPONSE {sequence:06d}]", flush=True)
        if response_head:
            print(response_head.decode("latin1", "replace"), end="", flush=True)
            if separator:
                print()
                print(f"      response-bytes={len(response_body)} preview={self._preview(response_body, 320)}", flush=True)
        else:
            print(f"      raw-response={self._preview(response, 320)}", flush=True)
        if request_path and response_path:
            print(f"[ARCHIVE {sequence:06d}] {request_path} | {response_path}", flush=True)
        print(f"[END EXCHANGE {sequence:06d}]", flush=True)

    def _dump_exchange(self, method: str, headers: bytes, body: bytes,
                       response: bytes) -> None:
        """Archive and optionally print one exact authorized exchange."""
        show = os.environ.get("P2S_SHOW_REQUESTS") == "1"
        if not self.dump_dir and not show:
            return

        self.dump_sequence += 1
        sequence = self.dump_sequence
        prefix = f"{sequence:06d}"
        request = headers + body
        request_path = None
        response_path = None
        request_sha = hashlib.sha256(request).hexdigest()
        body_sha = hashlib.sha256(body).hexdigest()
        response_sha = hashlib.sha256(response).hexdigest()

        if self.dump_dir:
            os.makedirs(self.dump_dir, exist_ok=True)
            request_path = os.path.join(self.dump_dir, prefix + ".request.gz")
            response_path = os.path.join(self.dump_dir, prefix + ".response.gz")
            meta_path = os.path.join(self.dump_dir, prefix + ".json")
            with open(request_path, "wb") as fh:
                fh.write(gzip.compress(request, compresslevel=6, mtime=0))
            with open(response_path, "wb") as fh:
                fh.write(gzip.compress(response, compresslevel=6, mtime=0))
            request_line = headers.split(b"\r\n", 1)[0].decode("ascii", "replace")
            metadata = {
                "sequence": sequence,
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
                "request_sha256": request_sha,
                "body_sha256": body_sha,
                "response_sha256": response_sha,
            }
            with open(meta_path, "w", encoding="utf-8") as fh:
                json.dump(metadata, fh, indent=2)
                fh.write("\n")

        if show:
            boundary = None
            content_type = next(
                (
                    line for line in headers.split(b"\r\n")
                    if line.lower().startswith(b"content-type:")
                ),
                b"",
            )
            marker = b"boundary="
            if marker in content_type:
                boundary = content_type.split(marker, 1)[1].strip()
            self._print_exchange(
                sequence, headers, body, boundary, response,
                request_path, response_path,
            )
'''


def patch_request_display(repo: Path) -> None:
    """Add live, concise output without printing multi-megabyte bodies."""
    path = repo / "exploit.py"
    source = path.read_text(encoding="utf-8")
    if "[REAL REQUEST " not in source:
        if OLD not in source:
            raise RuntimeError("request-dump helper pattern not found")
        source = source.replace(OLD, NEW, 1)
        path.write_text(source, encoding="utf-8")
