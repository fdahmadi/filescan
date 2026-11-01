#!/usr/bin/env python3
"""Scan sensitivity_demo samples under lenient / balanced / strict and print a matrix."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "testdata" / "sensitivity_demo"
DEFAULT_API = "http://127.0.0.1:8001/v1/scan"


def _multipart(path: Path, sensitivity: str, use_remote_intel: bool) -> tuple[bytes, str]:
    boundary = "----FileScanSensitivityBound"
    chunks: list[bytes] = []
    data = path.read_bytes()
    chunks.append(
        (
            f"--{boundary}\r\n"
            f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
            f"Content-Type: application/octet-stream\r\n\r\n"
        ).encode()
        + data
        + b"\r\n"
    )
    for name, value in (
        ("sensitivity", sensitivity),
        ("use_remote_intel", "true" if use_remote_intel else "false"),
    ):
        chunks.append(
            (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode()
        )
    body = b"".join(chunks) + f"--{boundary}--\r\n".encode()
    return body, boundary


def scan(
    path: Path,
    *,
    api: str,
    api_key: str,
    sensitivity: str,
    use_remote_intel: bool,
) -> dict:
    body, boundary = _multipart(path, sensitivity, use_remote_intel)
    req = urllib.request.Request(
        api,
        data=body,
        method="POST",
        headers={
            "X-API-Key": api_key,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        },
    )
    with urllib.request.urlopen(req, timeout=180) as resp:
        return json.load(resp)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", default=DEFAULT_API)
    parser.add_argument("--api-key", default="dev-demo-key")
    parser.add_argument(
        "--remote-intel",
        action="store_true",
        help="Enable abuse.ch / YARAify (slower)",
    )
    parser.add_argument(
        "--dir",
        type=Path,
        default=DEMO,
        help="Sample directory (default: testdata/sensitivity_demo)",
    )
    args = parser.parse_args()

    samples = sorted(
        p
        for p in args.dir.iterdir()
        if p.is_file() and p.name != "README.md" and not p.name.startswith(".")
    )
    if not samples:
        print(f"no samples in {args.dir}", file=sys.stderr)
        return 1

    print(f"{'file':28} {'lenient':12} {'balanced':12} {'strict':12} differs  flags")
    print("-" * 110)
    for path in samples:
        verdicts: dict[str, str] = {}
        flags: list[str] = []
        try:
            for sens in ("lenient", "balanced", "strict"):
                result = scan(
                    path,
                    api=args.api,
                    api_key=args.api_key,
                    sensitivity=sens,
                    use_remote_intel=args.remote_intel,
                )
                verdicts[sens] = str(result.get("verdict", "?"))
                if not flags:
                    for eng in result.get("engines") or []:
                        status = str(eng.get("status") or "")
                        if status in {"clean", "skipped"}:
                            continue
                        threats = eng.get("threats") or []
                        label = f"{eng.get('name')}:{status}"
                        if threats:
                            label += f"({','.join(str(t) for t in threats[:2])})"
                        flags.append(label)
        except urllib.error.URLError as exc:
            print(f"{path.name:28} ERROR {exc}", file=sys.stderr)
            continue

        differs = len(set(verdicts.values())) > 1
        mark = "yes" if differs else "no"
        print(
            f"{path.name:28} {verdicts['lenient']:12} {verdicts['balanced']:12} "
            f"{verdicts['strict']:12} {mark:7}  {', '.join(flags) or '—'}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
