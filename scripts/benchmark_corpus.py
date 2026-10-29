#!/usr/bin/env python3
"""Run FileScan engines against testdata/corpus and print a verdict table.

Usage (from repo root):
  PYTHONPATH=. python scripts/benchmark_corpus.py
  PYTHONPATH=. python scripts/benchmark_corpus.py --dir testdata/corpus
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.config import Settings
from app.services.orchestrator import ScanOrchestrator


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark FileScan on a corpus directory")
    parser.add_argument(
        "--dir",
        type=Path,
        default=ROOT / "testdata" / "corpus",
        help="Directory of sample files",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="Optional path to write full JSON results",
    )
    parser.add_argument(
        "--sensitivity",
        choices=("lenient", "balanced", "strict"),
        default="balanced",
        help="Verdict sensitivity mode",
    )
    args = parser.parse_args()

    corpus = args.dir
    if not corpus.is_dir():
        print(f"corpus dir not found: {corpus}", file=sys.stderr)
        return 1

    from app.models.schemas import Sensitivity

    settings = Settings(
        clamav_enabled=False,  # local bench should not require clamd
        lmd_enabled=False,
        capa_enabled=False,
        floss_enabled=False,
        abusech_enabled=False,
        yaraify_enabled=False,
        cache_enabled=False,
        yara_rules_dir=ROOT / "rules" / "yara",
        upload_dir=Path("/tmp/filescan/bench_uploads"),
        results_dir=Path("/tmp/filescan/bench_results"),
        allowlist_path=Path("/tmp/filescan/bench_allow.json"),
        denylist_path=Path("/tmp/filescan/bench_deny.json"),
    )
    orch = ScanOrchestrator(settings)
    sens = Sensitivity(args.sensitivity)

    rows: list[dict] = []
    print(f"sensitivity={sens.value}")
    print(f"{'file':<28} {'verdict':<12} {'engines (non-clean)'}")
    print("-" * 80)
    for path in sorted(corpus.iterdir()):
        if not path.is_file() or path.name.startswith(".") or path.suffix.lower() == ".md":
            continue
        result = orch.scan_file(path, path.name, sensitivity=sens)
        interesting = [
            f"{e.name}:{e.status.value}"
            for e in result.engines
            if e.status.value not in {"clean", "skipped", "unavailable"}
        ]
        print(f"{path.name:<28} {result.verdict.value:<12} {', '.join(interesting) or '-'}")
        rows.append(json.loads(result.model_dump_json()))

    if args.json_out:
        args.json_out.write_text(json.dumps(rows, indent=2), encoding="utf-8")
        print(f"\nWrote {args.json_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
