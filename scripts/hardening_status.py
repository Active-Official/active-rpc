#!/usr/bin/env python3
"""Validate the hardening map and regenerate the matrix block in STATUS.md.

The hardening program (ACTIVE-HARDENING-GUIDE-AND-CHECKLIST.md) requires that
every invariant and every checklist item name an automated check that really
exists. Hand-written status tables drift; this script makes drift a failure.

Checks are written as `<kind>:<ref>`:

    test:tests/unit_tests.rs::round_trip_preserves_values
    fuzz:decode
    vector:tests/vectors/invalid/limit.ainf
    gate:api-surface
    script:scripts/api_surface.py
    doc:docs/spec/security.md

`test:` references are resolved by parsing the named file for a `#[test]`
function. `gate:` references resolve through the `[gates]` table. `doc:` is
accepted for inventory rows but is never enough on its own for a critical
invariant: a document is not an automated check.

Usage:
    python scripts/hardening_status.py --check   # validate, fail on drift
    python scripts/hardening_status.py --write   # rewrite STATUS.md block
    python scripts/hardening_status.py --json    # machine-readable summary
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11
    sys.exit("hardening_status: Python 3.11+ is required (tomllib)")

BEGIN = "<!-- BEGIN GENERATED: hardening matrix (scripts/hardening_status.py) -->"
END = "<!-- END GENERATED: hardening matrix -->"

INVARIANTS = [f"I-{n}" for n in range(1, 13)]
# A derived control (for example promise single-settlement) is allowed as an
# extra row when it defends an invariant that the numbered list does not name
# directly. Core invariants are still mandatory.
DERIVED_PREFIXES = ("C-",)
INVARIANT_STATUS = {"covered", "partial", "gap", "n/a"}
PHASE_STATUS = {"done", "partial", "gap", "n/a"}
NEGATIVE_CONTROL_STATUS = {"implemented", "documented", "gap"}

CHECK_KINDS = ("test", "fuzz", "vector", "gate", "script", "doc")
TEST_RE = re.compile(
    r"#\[test\][^\n]*\n(?:\s*#\[[^\n]*\n)*\s*fn\s+([A-Za-z0-9_]+)", re.MULTILINE
)


class MapError(Exception):
    pass


def load_map(root: Path) -> dict:
    path = root / "docs" / "hardening" / "invariant-map.toml"
    if not path.exists():
        raise MapError(f"missing {path.relative_to(root)}")
    with path.open("rb") as handle:
        return tomllib.load(handle)


def test_names(root: Path, relative: str) -> set[str]:
    path = root / relative
    if not path.exists():
        raise MapError(f"test file not found: {relative}")
    source = path.read_text(encoding="utf-8", errors="replace")
    return set(TEST_RE.findall(source))


def resolve(root: Path, check: str, gates: dict) -> tuple[str, str]:
    """Return (kind, detail) for a check reference, or raise MapError."""
    if ":" not in check:
        raise MapError(f"check has no kind prefix: {check!r}")
    kind, ref = check.split(":", 1)
    if kind not in CHECK_KINDS:
        raise MapError(f"unknown check kind {kind!r} in {check!r}")
    if kind == "test":
        if "::" not in ref:
            raise MapError(f"test check needs <file>::<name>: {check!r}")
        relative, name = ref.split("::", 1)
        names = test_names(root, relative)
        if name not in names:
            raise MapError(f"test not found: {relative}::{name}")
        return kind, f"{relative}::{name}"
    if kind == "gate":
        if ref not in gates:
            raise MapError(f"gate not declared in [gates]: {ref}")
        return kind, gates[ref]
    if kind == "fuzz":
        relative = f"fuzz/fuzz_targets/{ref}.rs"
        if not (root / relative).exists():
            raise MapError(f"fuzz target not found: {relative}")
        return kind, relative
    if kind == "script":
        relative, _, fragment = ref.partition("#")
        path = root / relative
        if not path.exists():
            raise MapError(f"script path not found: {relative}")
        if fragment and f'"id": "{fragment}"' not in path.read_text(
            encoding="utf-8", errors="replace"
        ):
            raise MapError(f"script {relative} has no control named {fragment!r}")
        return kind, ref
    if not (root / ref).exists():
        raise MapError(f"{kind} path not found: {ref}")
    return kind, ref


def validate(root: Path, matrix: dict) -> tuple[dict, list[str]]:
    errors: list[str] = []
    gates = matrix.get("gates", {})
    repo = matrix.get("repo", {})

    for key in ("name", "version", "commit", "baseline_tag", "measured_at"):
        if not repo.get(key):
            errors.append(f"[repo] missing {key}")

    invariants = matrix.get("invariants", [])
    seen: set[str] = set()
    for item in invariants:
        ident = item.get("id", "")
        if ident in seen:
            errors.append(f"duplicate invariant {ident}")
        seen.add(ident)
        if ident not in INVARIANTS and not ident.startswith(DERIVED_PREFIXES):
            errors.append(f"unknown invariant id {ident!r}")
        status = item.get("status")
        if status not in INVARIANT_STATUS:
            errors.append(f"{ident}: bad status {status!r}")
        checks = item.get("checks", [])
        if status != "n/a" and not checks:
            errors.append(f"{ident}: {status} without any check")
        if status == "n/a" and not item.get("note"):
            errors.append(f"{ident}: n/a without a note")
        if item.get("critical"):
            if not item.get("negative_control_probe"):
                errors.append(f"{ident}: critical without negative_control_probe")
            if not item.get("negative_control_expected"):
                errors.append(f"{ident}: critical without negative_control_expected")
            nc_status = item.get("negative_control_status")
            if nc_status not in NEGATIVE_CONTROL_STATUS:
                errors.append(f"{ident}: bad negative_control_status {nc_status!r}")
            if nc_status == "implemented" and not item.get("negative_control_check"):
                errors.append(
                    f"{ident}: implemented control without negative_control_check"
                )
    missing = [ident for ident in INVARIANTS if ident not in seen]
    if missing:
        errors.append("invariants not mapped: " + ", ".join(missing))

    phases = matrix.get("phases", [])
    phase_ids: set[str] = set()
    for item in phases:
        ident = item.get("id", "")
        if ident in phase_ids:
            errors.append(f"duplicate phase item {ident}")
        phase_ids.add(ident)
        status = item.get("status")
        if status not in PHASE_STATUS:
            errors.append(f"{ident}: bad status {status!r}")
        if status == "done" and not item.get("checks"):
            errors.append(f"{ident}: done without an automated check")
        if status == "n/a" and not item.get("note"):
            errors.append(f"{ident}: n/a without a note")
    if not phases:
        errors.append("no phase items mapped")

    resolved: dict[str, tuple[str, str]] = {}
    for check in sorted(
        {c for item in invariants for c in item.get("checks", [])}
        | {c for item in phases for c in item.get("checks", [])}
        | {
            item["negative_control_check"]
            for item in invariants
            if item.get("negative_control_status") == "implemented"
        }
    ):
        try:
            resolved[check] = resolve(root, check, gates)
        except MapError as exc:
            errors.append(str(exc))
    return resolved, errors


def render(matrix: dict, resolved: dict[str, tuple[str, str]]) -> str:
    repo = matrix["repo"]
    invariants = matrix["invariants"]
    phases = matrix["phases"]
    gates = matrix.get("gates", {})

    lines = [BEGIN, ""]
    lines.append(
        f"**Repository:** `{repo['name']}` **version:** `{repo['version']}` "
        f"**baseline commit:** `{repo['commit']}` **baseline tag:** `{repo['baseline_tag']}` "
        f"**measured:** {repo['measured_at']}"
    )
    lines.append("")

    covered = sum(1 for i in invariants if i["status"] == "covered")
    partial = sum(1 for i in invariants if i["status"] == "partial")
    gaps = sum(1 for i in invariants if i["status"] == "gap")
    na = sum(1 for i in invariants if i["status"] == "n/a")
    done = sum(1 for p in phases if p["status"] == "done")
    p_partial = sum(1 for p in phases if p["status"] == "partial")
    p_gap = sum(1 for p in phases if p["status"] == "gap")
    p_na = sum(1 for p in phases if p["status"] == "n/a")
    counters = [
        item
        for item in invariants
        if item.get("critical") and item.get("negative_control_status") == "implemented"
    ]
    criticals = [item for item in invariants if item.get("critical")]
    lines.append(
        f"Invariants: {covered} covered, {partial} partial, {gaps} gap, {na} not applicable. "
        f"Checklist items: {done} done, {p_partial} partial, {p_gap} gap, {p_na} not applicable. "
        f"Criticals with an implemented negative control: {len(counters)}/{len(criticals)}. "
        f"Distinct automated checks resolved: {len(resolved)}."
    )
    lines.append("")

    lines.append("| Invariant | Meaning | Status | Checks | Negative control |")
    lines.append("|---|---|---|---|---|")
    for item in invariants:
        title = item.get("title", "").replace("|", "\\|")
        status = item["status"]
        count = len(item.get("checks", []))
        if item.get("critical"):
            nc = item.get("negative_control_status", "gap")
            control = f"{nc}"
        else:
            control = "-"
        lines.append(
            f"| **{item['id']}** | {title} | `{status}` | {count} | {control} |"
        )
    lines.append("")

    lines.append("| Item | Checklist item | Status | Evidence |")
    lines.append("|---|---|---|---|")
    for item in phases:
        title = item.get("title", "").replace("|", "\\|")
        evidence = ", ".join(f"`{c}`" for c in item.get("checks", [])) or "-"
        lines.append(
            f"| **{item['id']}** | {title} | `{item['status']}` | {evidence} |"
        )
    lines.append("")

    lines.append("### Check index")
    lines.append("")
    for item in invariants:
        checks = item.get("checks", [])
        if not checks:
            continue
        lines.append(
            f"<details><summary><strong>{item['id']}</strong> "
            f"({len(checks)} checks)</summary>"
        )
        lines.append("")
        for check in checks:
            detail = resolved.get(check, ("", ""))[1]
            lines.append(
                f"- `{check}`"
                + (
                    f" — {detail}"
                    if detail and detail != check.split(":", 1)[1]
                    else ""
                )
            )
        if item.get("critical"):
            lines.append("")
            lines.append(
                f"Negative control ({item.get('negative_control_status')}): "
                f"{item.get('negative_control_probe')} → expected: "
                f"{item.get('negative_control_expected')}"
            )
        lines.append("")
        lines.append("</details>")
        lines.append("")

    if gates:
        lines.append("### Gates referenced by the matrix")
        lines.append("")
        lines.append("| Gate | Command |")
        lines.append("|---|---|")
        for name, command in sorted(gates.items()):
            lines.append(f"| `{name}` | `{command}` |")
        lines.append("")

    lines.append(END)
    return "\n".join(lines)


def update_status(root: Path, block: str) -> bool:
    status = root / "docs" / "hardening" / "STATUS.md"
    if not status.exists():
        raise MapError(f"missing {status.relative_to(root)}")
    text = status.read_text(encoding="utf-8")
    start = text.find(BEGIN)
    end = text.find(END)
    if start == -1 or end == -1 or end < start:
        raise MapError("STATUS.md has no generated region markers")
    end += len(END)
    updated = text[:start] + block + text[end:]
    if updated == text:
        return False
    status.write_text(updated, encoding="utf-8", newline="\n")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--root", default=".")
    args = parser.parse_args()
    root = Path(args.root).resolve()

    try:
        matrix = load_map(root)
        resolved, errors = validate(root, matrix)
        block = render(matrix, resolved)
        if args.write:
            changed = update_status(root, block)
        else:
            changed = False
        if args.check:
            current = (root / "docs" / "hardening" / "STATUS.md").read_text(
                encoding="utf-8"
            )
            start = current.find(BEGIN)
            end = current.find(END)
            if start == -1 or end == -1:
                errors.append("STATUS.md generated region missing")
            elif current[start : end + len(END)] != block:
                errors.append(
                    "STATUS.md is stale; run scripts/hardening_status.py --write"
                )
    except MapError as exc:
        print(f"hardening map error: {exc}", file=sys.stderr)
        return 1

    summary = {
        "repo": matrix["repo"]["name"],
        "version": matrix["repo"]["version"],
        "commit": matrix["repo"]["commit"],
        "baseline_tag": matrix["repo"]["baseline_tag"],
        "invariants": len(matrix["invariants"]),
        "phase_items": len(matrix["phases"]),
        "checks_resolved": len(resolved),
        "invariant_status": {
            item["id"]: item["status"] for item in matrix["invariants"]
        },
        "phase_status": {item["id"]: item["status"] for item in matrix["phases"]},
        "errors": errors,
        "written": changed,
    }
    if args.json:
        print(json.dumps(summary, indent=2, sort_keys=True))
    else:
        if errors:
            for error in errors:
                print(f"error: {error}", file=sys.stderr)
        print(
            f"{summary['repo']} {summary['version']}: {summary['invariants']} invariants, "
            f"{summary['phase_items']} checklist items, {summary['checks_resolved']} checks, "
            f"{len(errors)} error(s)"
        )
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
