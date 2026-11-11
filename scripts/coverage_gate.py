#!/usr/bin/env python3
"""Fail when coverage falls below the checked-in floor.

Usage:
    cargo llvm-cov --locked --all-features --json --output-path coverage.json
    python scripts/coverage_gate.py coverage.json

    python scripts/coverage_gate.py --baseline docs/hardening/coverage-baseline-windows.json coverage.json

    python scripts/coverage_gate.py --update-baseline coverage.json

Checks, in order:

  1. Global totals. ``lines`` / ``regions`` / ``functions`` from the report
     totals must stay within ``ALLOWANCE`` of the checked-in baseline.
     This is the old check; on its own it is not enough, because a global
     average hides a module that lost coverage while another gained it.

  2. Per-file floors. Every file listed under ``"files"`` in the baseline
     carries its own ``lines`` / ``functions`` floor (percent). A regression
     in one security-critical module can no longer be averaged away by the
     1,300-test bulk. The floor is the measured value at the time the entry
     was last ratcheted up; see ``--update-baseline``.

  3. No new uncovered function. Every file listed under ``"files"`` also
     carries the explicit list of functions that are currently uncovered in
     that file. The gate fails if the report shows *any* uncovered function
     that is not already on that list. The old global gate permanently
     grandfathered untested code: a function that had never run passed the
     gate forever as long as the average held. From here on, new code that
     ships without a test fails the gate, and the only way to admit a new
     uncovered function is to list it in the baseline explicitly, in a
     reviewed diff.

Function identity is the definition span, ``src/kernel.rs:780-797`` (file
plus first-region start/end lines from the llvm-cov report). Spans are used
because the report's function names are mangled per instantiation (one
logical function appears ~5 times under different mangled names, and the
crate-hash segments in those names change when the crate graph changes),
while a definition span is stable across rebuilds, platforms and llvm-cov
versions. A span resolves to a function by opening the file at that line.
A function is uncovered when every instantiation of its span has execution
count 0.

The report must be the FULL llvm-cov JSON (no ``--summary-only``): the
per-file and per-function checks need the ``files`` and ``functions``
sections. A summary-only report is rejected with exit code 2 and a
message saying how to re-run it. Silently skipping the per-file checks
would re-introduce exactly the hole this gate closes.

``--update-baseline`` regenerates the baseline from a fresh report: global
metrics and per-file floors are set to the measured values and the
uncovered-function lists are refreshed. It REFUSES to lower any floor:
floors only ratchet up. Run it deliberately after landing tests that raise
coverage, and review the diff before committing it. A coverage drop that
is real (not toolchain noise) must be fixed by adding tests, not by
re-baselining.

Two baselines exist, one per platform the coverage is measured on
(TEST-02): ``docs/hardening/coverage-baseline.json`` (Linux, the
``coverage`` job in ``nightly.yml``) and
``docs/hardening/coverage-baseline-windows.json`` (Windows, the
``coverage-windows`` job in ``nightly.yml``). Pass ``--baseline`` to
select one; the default is the Linux baseline. The floors apply on any
platform, but the uncovered-function lists are platform-specific, so
each platform's report is gated against its own platform's baseline. A
function covered on Linux through platform-gated code (a Unix file-lock
path, for instance) is legitimately uncovered on Windows, and the Linux
baseline flags it there (receipts.rs:1103 and :661 on a Windows
report): that is a platform gap to record, not a regression.
``--update-baseline`` regenerates whichever baseline ``--baseline``
names. A macOS baseline does not exist yet: no macOS host is available
to measure one, so macOS coverage is not gated (the macOS gate in
ci.yml compiles and tests; it does not measure coverage). That is a
TEST-02 follow-up, not a gap in this gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# Toolchain and platform shifts move line coverage by a few tenths of a point.
# One point is the noise allowance; a real regression is larger and persistent.
ALLOWANCE = 1.0


def _normalize(path: str) -> str:
    return path.replace("\\", "/")


def _relative_key(report_path: str, relatives: list[str]) -> str | None:
    """Repo-relative key for a report path, or None if it is not gated.

    The longest matching baseline key wins, so ``src/transport/mod.rs``
    is not also attributed to ``src/mod.rs``.
    """
    normalized = _normalize(report_path)
    best: str | None = None
    for relative in relatives:
        suffix = "/" + _normalize(relative).lstrip("/")
        if normalized.endswith(suffix):
            if best is None or len(relative) > len(best):
                best = relative
    return best


def _span_key(relative: str, regions: list) -> str | None:
    """``src/kernel.rs:780-797`` for a function's first region, or None."""
    if not regions:
        return None
    first = regions[0]
    return f"{relative}:{first[0]}-{first[2]}"


def _uncovered_spans(data: dict, relatives: list[str]) -> dict[str, set[str]]:
    """Map repo-relative file -> set of uncovered definition spans.

    Instantiations of one logical function share a definition span; the
    span is uncovered only when every instantiation has count 0.
    """
    best_count: dict[str, int] = {}
    for fn in data.get("functions", []):
        regions = fn.get("regions") or []
        if not regions:
            continue
        count = int(fn.get("count", 0))
        for filename in fn.get("filenames", []):
            relative = _relative_key(filename, relatives)
            if relative is None:
                continue
            key = _span_key(relative, regions)
            if key is None:
                continue
            best_count[key] = max(best_count.get(key, 0), count)
    uncovered: dict[str, set[str]] = {relative: set() for relative in relatives}
    for key, count in best_count.items():
        if count == 0:
            relative = key.rsplit(":", 1)[0]
            uncovered[relative].add(key)
    return uncovered


def _match_file(files: dict[str, dict], relative: str) -> dict | None:
    """Find the report entry for a repo-relative path (suffix match).

    llvm-cov reports absolute paths that differ per machine and per
    platform (``F:/.../src/kernel.rs`` on Windows, ``/work/src/kernel.rs``
    in Docker/CI). The baseline stores repo-relative paths; the match is
    the report path whose normalized form ends with ``/<relative>``.
    """
    suffix = "/" + _normalize(relative).lstrip("/")
    candidates = [f for p, f in files.items() if p.endswith(suffix)]
    if not candidates:
        return None
    # Longest path wins if several entries share the suffix.
    candidates.sort(key=lambda f: len(_normalize(f["filename"])), reverse=True)
    return candidates[0]


def check(report: dict, baseline: dict) -> list[str]:
    """Return the list of failure messages (empty means the gate passes)."""
    failures: list[str] = []
    data = report["data"][0]
    totals = data["totals"]

    for metric in ("lines", "regions", "functions"):
        measured = float(totals[metric]["percent"])
        floor = float(baseline[metric]) - ALLOWANCE
        status = "ok" if measured >= floor else "FAIL"
        print(f"{metric:10} {measured:6.2f}%  floor {floor:6.2f}%  {status}")
        if measured < floor:
            failures.append(f"{metric}: {measured:.2f}% < {floor:.2f}%")

    files = {_normalize(f["filename"]): f for f in data.get("files", [])}
    baseline_files = baseline.get("files", {})
    relatives = sorted(baseline_files)
    uncovered = _uncovered_spans(data, relatives)

    for relative in relatives:
        entry = baseline_files[relative]
        matched = _match_file(files, relative)
        if matched is None:
            failures.append(f"{relative}: not present in coverage report")
            print(f"{relative}: FAIL (missing from report)")
            continue
        summary = matched["summary"]
        for metric in ("lines", "functions"):
            measured = float(summary[metric]["percent"])
            floor = float(entry[metric]) - ALLOWANCE
            status = "ok" if measured >= floor else "FAIL"
            print(f"{relative} {metric:10} {measured:6.2f}%  floor {floor:6.2f}%  {status}")
            if measured < floor:
                failures.append(
                    f"{relative} {metric}: {measured:.2f}% < {floor:.2f}%"
                )
        allowed = set(entry.get("uncovered_functions", []))
        current = uncovered.get(relative, set())
        new_uncovered = sorted(current - allowed)
        fixed = sorted(allowed - current)
        if new_uncovered:
            print(
                f"{relative}: FAIL new uncovered function(s): "
                + ", ".join(new_uncovered)
            )
            failures.append(
                f"{relative}: new uncovered function(s): "
                + ", ".join(new_uncovered)
            )
        else:
            print(f"{relative}: no new uncovered functions")
        if fixed:
            print(
                f"{relative}: note: {len(fixed)} function(s) now covered "
                "(update the baseline to record the gain)"
            )
    return failures


def regenerate(report: dict, baseline: dict) -> dict:
    """Build a new baseline from a fresh report; never lower a floor."""
    data = report["data"][0]
    totals = data["totals"]
    new: dict = {
        "lines": round(float(totals["lines"]["percent"]), 2),
        "regions": round(float(totals["regions"]["percent"]), 2),
        "functions": round(float(totals["functions"]["percent"]), 2),
        "files": {},
    }
    files = {_normalize(f["filename"]): f for f in data.get("files", [])}
    relatives = sorted(baseline.get("files", {}))
    uncovered = _uncovered_spans(data, relatives)
    lowered: list[str] = []
    for relative in relatives:
        entry = baseline["files"][relative]
        matched = _match_file(files, relative)
        if matched is None:
            raise SystemExit(f"baseline file {relative} not present in report")
        summary = matched["summary"]
        lines = round(float(summary["lines"]["percent"]), 2)
        functions = round(float(summary["functions"]["percent"]), 2)
        for metric, value in (("lines", lines), ("functions", functions)):
            if value < float(entry[metric]):
                lowered.append(f"{relative} {metric}: {value:.2f} < {entry[metric]:.2f}")
        new["files"][relative] = {
            "lines": lines,
            "functions": functions,
            "uncovered_functions": sorted(uncovered.get(relative, set())),
        }
    if lowered:
        print(
            "refusing to lower a floor (ratchet only moves up):\n  "
            + "\n  ".join(lowered),
            file=sys.stderr,
        )
        raise SystemExit(1)
    for metric in ("lines", "regions", "functions"):
        if new[metric] < float(baseline[metric]):
            print(
                f"refusing to lower the global {metric} floor: "
                f"{new[metric]:.2f} < {baseline[metric]:.2f}",
                file=sys.stderr,
            )
            raise SystemExit(1)
    return new


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("coverage", help="llvm-cov JSON report (full, not --summary-only)")
    parser.add_argument(
        "--baseline",
        default="docs/hardening/coverage-baseline.json",
        help="checked-in floor",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="regenerate the baseline from this report instead of checking",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    baseline_path = root / args.baseline
    baseline = json.loads(baseline_path.read_text(encoding="utf-8"))
    report = json.loads(Path(args.coverage).read_text(encoding="utf-8"))
    data = report["data"][0]
    if "files" not in data or "functions" not in data:
        print(
            "coverage report is summary-only; the per-file and "
            "per-function checks need the full JSON.\n"
            "Re-run without --summary-only:\n"
            "  cargo llvm-cov --locked --all-features --json "
            "--output-path coverage.json",
            file=sys.stderr,
        )
        return 2

    if args.update_baseline:
        new = regenerate(report, baseline)
        baseline_path.write_text(
            json.dumps(new, indent=2) + "\n", encoding="utf-8"
        )
        print(f"baseline updated: {baseline_path}")
        return 0

    failures = check(report, baseline)
    if failures:
        print("coverage regression: " + "; ".join(failures), file=sys.stderr)
        return 1
    print("coverage floor met")
    return 0


if __name__ == "__main__":
    sys.exit(main())
