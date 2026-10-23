#!/usr/bin/env python3
"""Run the local calibration factory over a named PHP image matrix."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import subprocess
import sys
from pathlib import Path

from profile_inventory import load_profiles

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SOLVER = ROOT / "solver"
CALIBRATOR = HERE / "calibrate_image.py"
PROFILE_DIR = SOLVER / "profiles"
LOG_DIR = ROOT / "runtime" / "research-work" / "matrix-logs"

sys.path.insert(0, str(SOLVER))

VERIFIED_MATRIX = [
    {"image": "php:8.4.25-apache", "platform": "linux/arm64", "version": "8.4.25", "arch": "aarch64"},
    {"image": "php:8.4.26-apache", "platform": "linux/amd64", "version": "8.4.26", "arch": "amd64"},
    {"image": "php:8.5.10-apache", "platform": "linux/arm64", "version": "8.5.10", "arch": "aarch64"},
    {"image": "php:8.5.11-apache", "platform": "linux/arm64", "version": "8.5.11", "arch": "aarch64"},
    {"image": "php:8.5.11-apache", "platform": "linux/amd64", "version": "8.5.11", "arch": "amd64"},
]

BRANCH_MATRIX = [
    {"image": "php:5.4.45-apache", "platform": "linux/amd64", "version": "5.4.45", "arch": "amd64"},
    {"image": "php:5.5.38-apache", "platform": "linux/amd64", "version": "5.5.38", "arch": "amd64"},
    {"image": "php:5.6.40-apache", "platform": "linux/amd64", "version": "5.6.40", "arch": "amd64"},
    {"image": "php:7.0.33-apache", "platform": "linux/amd64", "version": "7.0.33", "arch": "amd64"},
    {"image": "php:7.1.33-apache", "platform": "linux/amd64", "version": "7.1.33", "arch": "amd64"},
    {"image": "php:7.2.34-apache", "platform": "linux/amd64", "version": "7.2.34", "arch": "amd64"},
    {"image": "php:7.3.33-apache", "platform": "linux/amd64", "version": "7.3.33", "arch": "amd64"},
    {"image": "php:7.4.33-apache", "platform": "linux/amd64", "version": "7.4.33", "arch": "amd64"},
    {"image": "php:8.0.30-apache", "platform": "linux/amd64", "version": "8.0.30", "arch": "amd64"},
    {"image": "php:8.1.34-apache", "platform": "linux/amd64", "version": "8.1.34", "arch": "amd64"},
    {"image": "php:8.2.34-apache", "platform": "linux/amd64", "version": "8.2.34", "arch": "amd64"},
    {"image": "php:8.3.35-apache", "platform": "linux/amd64", "version": "8.3.35", "arch": "amd64"},
    {"image": "php:8.4.26-apache", "platform": "linux/amd64", "version": "8.4.26", "arch": "amd64"},
    {"image": "php:8.5.11-apache", "platform": "linux/amd64", "version": "8.5.11", "arch": "amd64"},
]

HISTORICAL_MATRIX = [
    {"image": "php:7.4-apache", "platform": "linux/arm64", "version": "7.4.33", "arch": "aarch64"},
    {"image": "php:8.0-apache", "platform": "linux/arm64", "version": "8.0.30", "arch": "aarch64"},
    {"image": "php:8.1-apache", "platform": "linux/arm64", "version": "8.1.34", "arch": "aarch64"},
    {"image": "php:8.2.0-apache", "platform": "linux/arm64", "version": "8.2.0", "arch": "aarch64"},
    {"image": "php:8.2.34-apache", "platform": "linux/arm64", "version": "8.2.34", "arch": "aarch64"},
    {"image": "php:8.3.0-apache", "platform": "linux/arm64", "version": "8.3.0", "arch": "aarch64"},
    {"image": "wordpress:7.1.1-apache", "platform": "linux/arm64", "version": "8.3.33", "arch": "aarch64"},
    {"image": "php:8.3.35-apache", "platform": "linux/arm64", "version": "8.3.35", "arch": "aarch64"},
    {"image": "php:8.5.0-apache", "platform": "linux/arm64", "version": "8.5.0", "arch": "aarch64"},
]

MATRIXES = {
    "verified": VERIFIED_MATRIX,
    "branches": BRANCH_MATRIX,
    "historical": HISTORICAL_MATRIX,
    "full": [*VERIFIED_MATRIX, *BRANCH_MATRIX, *HISTORICAL_MATRIX],
}


def deduplicate(entries: list[dict[str, str | None]]) -> list[dict[str, str | None]]:
    seen: set[tuple[str, str | None]] = set()
    result = []
    for entry in entries:
        identity = (str(entry["image"]), entry["platform"])
        if identity in seen:
            continue
        seen.add(identity)
        result.append(entry)
    return result


def existing_profile(version: str, arch: str) -> dict | None:
    for row in load_profiles():
        if row["php_version"] == version and row["arch"] == arch:
            return row["_data"]
    return None


def run_entry(
    entry: dict[str, str | None],
    attempts: int,
    timeout: float,
    force: bool,
) -> dict:
    image = str(entry["image"])
    platform = entry["platform"]
    version = str(entry["version"])
    arch = str(entry["arch"])
    print(f"[*] {image} [{platform or 'host'}] as {version}/{arch}", flush=True)

    best: dict | None = None
    last_returncode = 0
    log_paths: list[Path] = []
    for attempt in range(1, attempts + 1):
        print(f"    attempt {attempt}/{attempts}", flush=True)
        command = [sys.executable, str(CALIBRATOR), "--image", image]
        if platform:
            command += ["--platform", platform]
        if force:
            command.append("--force")

        LOG_DIR.mkdir(parents=True, exist_ok=True)
        safe_image = image.replace("/", "_").replace(":", "_")
        log_path = LOG_DIR / f"{safe_image}-{platform or 'host'}-{attempt}.log"
        log_paths.append(log_path)
        try:
            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
            log_path.write_text(process.stdout, encoding="utf-8")
            last_returncode = process.returncode
        except subprocess.TimeoutExpired as exc:
            output = exc.stdout if isinstance(exc.stdout, str) else ""
            log_path.write_text(output + f"\n[!] timed out after {timeout}s\n", encoding="utf-8")
            last_returncode = 124

        current = existing_profile(version, arch)
        if current and (best is None or current.get("rce") is True):
            best = current
            if current.get("rce") is True:
                break

    status = "rce" if best and best.get("rce") is True else "no-rce" if best else "failed"
    return {
        "image": image,
        "platform": platform or "host",
        "php_version": version,
        "arch": arch,
        "status": status,
        "rce": bool(best and best.get("rce") is True),
        "profile_status": best.get("status") if best else None,
        "exit_code": last_returncode,
        "attempts": attempts,
        "logs": [str(path.relative_to(HERE.parent)) for path in log_paths],
    }


def markdown_report(report: dict) -> str:
    lines = [
        "# PHP2Shell calibration matrix report",
        "",
        f"Generated: {report['generated_at']}",
        "",
        "| Image | Platform | PHP | Arch | Result | Profile status | Attempts |",
        "|---|---|---|---|---|---|---:|",
    ]
    for row in report["results"]:
        result = "✅ RCE" if row["rce"] else "❌ no RCE"
        lines.append(
            f"| `{row['image']}` | {row['platform']} | {row['php_version']} | "
            f"{row['arch']} | {result} | {row['profile_status'] or '-'} | {row['attempts']} |"
        )
    total = len(report["results"])
    enabled = sum(row["rce"] for row in report["results"])
    lines.extend(["", f"Entries: **{total}**; verified RCE after run: **{enabled}**."])
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--set", choices=MATRIXES, default="verified", help="matrix to run")
    parser.add_argument("--attempts", type=int, default=3, help="attempts per probabilistic entry")
    parser.add_argument("--timeout", type=float, default=1800, help="per calibration timeout")
    parser.add_argument("--refresh", action="store_true", help="run even when a profile already exists")
    parser.add_argument("--force", action="store_true", help="pass --force to the calibrator")
    parser.add_argument("--stop-on-error", action="store_true")
    parser.add_argument("--list", action="store_true", help="show the selected matrix and exit")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--json", type=Path, help="write JSON report")
    parser.add_argument("--markdown", type=Path, help="write Markdown report")
    args = parser.parse_args()

    if args.attempts <= 0 or args.timeout <= 0:
        parser.error("--attempts and --timeout must be positive")

    entries = deduplicate(MATRIXES[args.set])
    if args.list or args.dry_run:
        for entry in entries:
            profile = existing_profile(str(entry["version"]), str(entry["arch"]))
            state = "RCE" if profile and profile.get("rce") else "profile" if profile else "missing"
            print(f"{entry['image']}\t{entry['platform'] or 'host'}\t{entry['version']}\t{entry['arch']}\t{state}")
        return 0

    results = []
    failed = False
    for entry in entries:
        profile = existing_profile(str(entry["version"]), str(entry["arch"]))
        if profile and not args.refresh:
            print(
                f"[=] {entry['image']} [{entry['platform'] or 'host'}]: existing profile "
                f"({profile.get('status', 'unknown')}); use --refresh to rerun"
            )
            results.append({
                **entry,
                "php_version": entry["version"],
                "platform": entry["platform"] or "host",
                "status": "rce" if profile.get("rce") is True else "no-rce",
                "rce": profile.get("rce") is True,
                "profile_status": profile.get("status"),
                "exit_code": 0,
                "attempts": 0,
                "logs": [],
            })
            continue

        try:
            result = run_entry(entry, args.attempts, args.timeout, args.force)
            results.append(result)
            if result["status"] == "failed" and args.stop_on_error:
                failed = True
                break
        except KeyboardInterrupt:
            failed = True
            break

    report = {
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "matrix": args.set,
        "attempts": args.attempts,
        "results": results,
    }
    json_path = args.json or HERE / "work" / "matrix-report.json"
    markdown_path = args.markdown or HERE / "work" / "matrix-report.md"
    json_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(markdown_report(report), encoding="utf-8")
    print(f"[+] JSON report: {json_path}")
    print(f"[+] Markdown report: {markdown_path}")

    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
