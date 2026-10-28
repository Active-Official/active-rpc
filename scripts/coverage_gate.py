#!/usr/bin/env python3
"""Fail when coverage falls below the checked-in floor.

Usage:
    cargo llvm-cov --locked --all-features --json --summary-only --output-path coverage.json
    python scripts/coverage_gate.py coverage.json

The floor is the measured baseline minus a small allowance for toolchain and
platform noise. It catches a regression, not a one-off fluctuation.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Toolchain and platform shifts move line coverage by a few tenths of a point.
# One point is the noise allowance; a real regression is larger and persistent.
ALLOWANCE = 1.0

parser = argparse.ArgumentParser()
parser.add_argument("coverage", help="llvm-cov JSON summary")
parser.add_argument(
    "--baseline",
    default="docs/hardening/coverage-baseline.json",
    help="checked-in floor",
)
args = parser.parse_args()


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    baseline = json.loads((root / args.baseline).read_text(encoding="utf-8"))
    report = json.loads(Path(args.coverage).read_text(encoding="utf-8"))
    totals = report["data"][0]["totals"]

    failures = []
    for metric in ("lines", "regions", "functions"):
        measured = float(totals[metric]["percent"])
        floor = float(baseline[metric]) - ALLOWANCE
        status = "ok" if measured >= floor else "FAIL"
        print(f"{metric:10} {measured:6.2f}%  floor {floor:6.2f}%  {status}")
        if measured < floor:
            failures.append(f"{metric}: {measured:.2f}% < {floor:.2f}%")

    if failures:
        print("coverage regression: " + ", ".join(failures), file=sys.stderr)
        sys.exit(1)
    print("coverage floor met")


if __name__ == "__main__":
    sys.exit(main())

