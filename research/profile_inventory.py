#!/usr/bin/env python3
"""Inspect and validate the local PHP2Shell calibration inventory."""

from __future__ import annotations

import argparse
import csv
import io
import json
import sys
from pathlib import Path
from typing import Any

PROFILE_DIR = Path(__file__).resolve().parent.parent / "solver" / "profiles"
COLUMNS = (
    "php_version", "arch", "distro", "image", "stage1", "stage2",
    "zif_system", "zval_ptr_dtor", "htdata", "heap_leak", "libphp_leak",
    "rce", "status", "file",
)


def load_profiles(directory: Path = PROFILE_DIR) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.json")):
        if path.name == "schema.json":
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"{path}: invalid JSON: {exc}") from exc
        stages = data.get("stages", {})
        libphp = data.get("libphp", {})
        measured = data.get("measured", {})
        records.append({
            "php_version": data.get("php_version", "?"),
            "arch": data.get("arch", "?"),
            "distro": data.get("distro", "?"),
            "image": data.get("image", "?"),
            "stage1": (
                f"{stages.get('stage1_n')}/{stages.get('stage1_forge_len')}"
                if stages.get("stage1_n") else "-"
            ),
            "stage2": (
                f"{stages.get('stage2_t')}/{stages.get('stage2_v')}"
                if stages.get("stage2_t") else "-"
            ),
            "zif_system": libphp.get("zif_system", "-"),
            "zval_ptr_dtor": libphp.get("zval_ptr_dtor", "-"),
            "htdata": libphp.get("htdata") or "-",
            "heap_leak": bool(stages.get("stage1_n")),
            "libphp_leak": bool(measured.get("libphp_base")),
            "rce": data.get("rce") is True,
            "status": data.get("status", "unknown"),
            "file": path.name,
            "_path": path,
            "_data": data,
        })
    return records


def markdown(records: list[dict[str, Any]]) -> str:
    headers = COLUMNS[:-1]
    lines = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    for row in records:
        values = []
        for key in headers:
            value = row[key]
            if isinstance(value, bool):
                value = "yes" if value else "no"
            values.append(str(value).replace("|", "\\|"))
        lines.append("| " + " | ".join(values) + " |")
    enabled = sum(row["rce"] for row in records)
    lines.extend([
        "",
        f"Profiles: **{len(records)}**; verified RCE: **{enabled}**.",
    ])
    return "\n".join(lines) + "\n"


def csv_text(records: list[dict[str, Any]]) -> str:
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=COLUMNS, extrasaction="ignore")
    writer.writeheader()
    for row in records:
        writer.writerow({key: row[key] for key in COLUMNS})
    return buffer.getvalue()


def validate(records: list[dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    identities: set[tuple[str, str, str]] = set()
    for row in records:
        path: Path = row["_path"]
        data: dict[str, Any] = row["_data"]
        expected_prefix = f"{row['php_version']}-{row['arch']}-"
        if not path.name.startswith(expected_prefix):
            errors.append(f"{path.name}: filename must start with {expected_prefix!r}")
        identity = (str(row["php_version"]), str(row["arch"]), str(row["distro"]))
        if identity in identities:
            errors.append(f"{path.name}: duplicate version/arch/distro profile")
        identities.add(identity)

        if data.get("verified") is not data.get("rce"):
            errors.append(f"{path.name}: verified and rce must agree")
        if row["rce"]:
            if not all(row[key] for key in ("heap_leak", "libphp_leak")):
                errors.append(f"{path.name}: RCE profile lacks leak evidence")
            if not row["htdata"] or row["htdata"] == "-":
                errors.append(f"{path.name}: RCE profile lacks htdata")
            if row["stage1"] == "-" or row["stage2"] == "-":
                errors.append(f"{path.name}: RCE profile lacks heap geometry")
        else:
            if row["htdata"] != "-":
                errors.append(f"{path.name}: unverified profile must not claim htdata")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--format", choices=("markdown", "csv", "json"), default="markdown")
    parser.add_argument("--enabled", action="store_true", help="only verified RCE profiles")
    parser.add_argument("--output", type=Path, help="write output here instead of stdout")
    parser.add_argument("--check", action="store_true", help="validate profiles and exit nonzero on errors")
    args = parser.parse_args()

    try:
        records = load_profiles()
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    errors = validate(records)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)

    if args.enabled:
        records = [row for row in records if row["rce"]]

    if args.format == "markdown":
        output = markdown(records)
    elif args.format == "csv":
        output = csv_text(records)
    else:
        output = json.dumps([
            {key: row[key] for key in COLUMNS} for row in records
        ], indent=2) + "\n"

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
        print(f"[+] inventory written: {args.output}")
    elif not args.check:
        print(output, end="" if output.endswith("\n") else "\n")

    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
