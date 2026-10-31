#!/usr/bin/env python3
"""Performance regression gate for Active RPC.

Reads the JSON emitted by `examples/perf_matrix` and enforces:

1. **Tail stability**: p95 <= p50 * limit + slack, where the slack absorbs one
   scheduler hiccup (`max(100us, p50/2)`). A kernel call batch allows 5x, the
   envelope operations 4x.
2. **Linear scaling**: the 4k-argument shape may cost at most 10x (encode),
   12x (decode) or 12x (call batch) the 1k shape.
3. **Optional absolute baseline** (`--baseline`): p50 <= 1.6x and p99 <= 3.0x a
   recorded baseline for a release machine class.

`--update` writes the baseline only when every check passed. Malformed input is
a gate failure, never a traceback.

Usage:
    cargo run --release --example perf_matrix | python scripts/perf_gate.py -
    python scripts/perf_gate.py out.json --baseline docs/spec/perf-baseline.json
    python scripts/perf_gate.py out.json --update docs/spec/perf-baseline.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

TAIL_LIMIT = 4.0
TAIL_LIMIT_BY_PREFIX = {"call": 5.0}
SCALING_LIMIT = {"encode": 10.0, "decode": 12.0, "call": 12.0}
BASELINE_P50 = 1.6
BASELINE_P99 = 3.0
MIN_SLACK_NS = 100_000


def load(path: str) -> dict:
    if path == "-":
        return json.load(sys.stdin)
    return json.loads(Path(path).read_text(encoding="utf-8"))


def positive(sample: object, key: str) -> float | None:
    """A positive numeric sample, or None for anything malformed."""
    if not isinstance(sample, dict):
        return None
    value = sample.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if value > 0 else None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("matrix", help="perf matrix JSON path, or - for stdin")
    parser.add_argument("--baseline", help="absolute baseline to compare against")
    parser.add_argument("--update", help="write this matrix as the new baseline")
    parser.add_argument("--schema", default="active-rpc/perf-matrix/1")
    args = parser.parse_args()

    matrix = load(args.matrix)
    failures: list[str] = []

    def fail(message: str) -> None:
        failures.append(message)
        print(f"FAIL {message}")

    if not isinstance(matrix, dict) or matrix.get("schema") != args.schema:
        print(
            f"FAIL schema {matrix.get('schema') if isinstance(matrix, dict) else matrix!r}"
        )
        return 1
    ops = matrix.get("ops")
    if not isinstance(ops, dict) or not ops:
        print("FAIL matrix has no operations")
        return 1

    for name, sample in ops.items():
        p50 = positive(sample, "p50_ns")
        p95 = positive(sample, "p95_ns") or positive(sample, "p99_ns")
        p99 = positive(sample, "p99_ns")
        if p50 is None or p95 is None or p99 is None or p95 < p50 or p99 < p95:
            fail(f"{name}: p50/p95/p99 must be positive and ordered")
            continue
        limit = TAIL_LIMIT_BY_PREFIX.get(name.split("_")[0], TAIL_LIMIT)
        slack = max(MIN_SLACK_NS, p50 * 0.5)
        tail_limit = p50 * limit + slack
        if p95 > tail_limit:
            fail(f"{name}: p95 {p95:.0f}ns exceeds {tail_limit:.0f}ns")
        else:
            print(f"ok   {name}: p95/p50 = {p95 / p50:.2f}")

    for prefix, limit in SCALING_LIMIT.items():
        small = positive(ops.get(f"{prefix}_1k"), "p50_ns")
        large = positive(ops.get(f"{prefix}_4k"), "p50_ns")
        if small is None or large is None:
            fail(f"{prefix}: missing or malformed 1k/4k pair")
            continue
        ratio = large / small
        if ratio > limit:
            fail(f"{prefix}: 4k/1k scaling {ratio:.1f} exceeds {limit}")
        else:
            print(f"ok   {prefix}: 4k/1k = {ratio:.1f}x")

    sizes = matrix.get("sizes")
    if not isinstance(sizes, dict) or not (
        isinstance(sizes.get("small_bytes"), (int, float))
        and isinstance(sizes.get("large_bytes"), (int, float))
        and sizes["large_bytes"] > sizes["small_bytes"] > 0
    ):
        fail("encoded size did not grow with the shape")

    if args.baseline:
        baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
        base_ops = baseline.get("ops") if isinstance(baseline, dict) else None
        if not isinstance(base_ops, dict):
            fail("baseline has no operations")
        else:
            for name, sample in ops.items():
                base = base_ops.get(name)
                if not isinstance(base, dict):
                    fail(f"{name}: no baseline sample (regenerate the baseline)")
                    continue
                for key, factor in (("p50_ns", BASELINE_P50), ("p99_ns", BASELINE_P99)):
                    current = positive(sample, key)
                    recorded = positive(base, key)
                    if current is None or recorded is None:
                        fail(f"{name}.{key}: missing or zero sample")
                        continue
                    ratio = current / recorded
                    if ratio > factor:
                        fail(f"{name}.{key}: {ratio:.1f}x baseline exceeds {factor}x")

    if failures:
        if args.update:
            print(f"refusing to update the baseline: {len(failures)} failure(s)")
        print(f"\n{len(failures)} perf gate failure(s)")
        return 1

    if args.update:
        Path(args.update).write_text(
            json.dumps(matrix, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        print(f"baseline written to {args.update}")

    print("\nperf gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
