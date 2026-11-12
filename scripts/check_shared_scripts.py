#!/usr/bin/env python3
"""Cross-repo shared-script divergence lint (TEST-12).

The files listed in `scripts/shared-scripts.txt` are maintained by copy in
active-rpc and active-infinity and must stay byte-identical: a bug fix or a
threshold change in one copy has to land in the other, or the two repos'
gates silently disagree. That already happened once: the TEST-01/TEST-02
hardening of `coverage_gate.py` (per-file floors, no-new-uncovered-function,
`--update-baseline`, Windows baseline) landed in this repo on 2026-11-11
and was never mirrored, so Infinity still gates on the old global-totals
script. This lint is the fix the audit recommends (round-2 report, Part F,
item F4): a CI check that fails when a listed file differs between the
repos, so a fix in one repo either lands in both or fails loudly.

Usage:
    python3 scripts/check_shared_scripts.py [--other-repo PATH]
    python3 scripts/check_shared_scripts.py --other-repo ../active-infinity
    python3 scripts/check_shared_scripts.py --other-repo active-infinity

`--other-repo` is the active-infinity checkout to compare against. It
defaults to the sibling checkout `../active-infinity` next to this repo
(the layout on the audit machines). In CI the `shared-scripts` job checks
out Active-Official/active-infinity at `active-infinity` and passes it
explicitly. `--root` overrides the repo root (derived from this file's
location); it exists so the lint can be exercised against fixture trees.

Exit codes: 0 = every listed file is byte-identical in both repos;
1 = at least one listed file diverges or is missing on one side;
2 = the manifest or the other repo is unusable (not a divergence, a setup
error: fix the invocation, not the scripts).
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import sys
from pathlib import Path

# Cap for the per-file diff shown on divergence: enough to see what moved,
# short enough that a wholly rewritten file does not flood the CI log.
MAX_DIFF_LINES = 40


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_manifest(manifest_path: Path) -> list[str]:
    if not manifest_path.is_file():
        print(f"manifest not found: {manifest_path}", file=sys.stderr)
        raise SystemExit(2)
    names: list[str] = []
    for line in manifest_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        names.append(stripped)
    if not names:
        print(f"manifest lists no files: {manifest_path}", file=sys.stderr)
        raise SystemExit(2)
    seen: set[str] = set()
    for name in names:
        # The manifest is trusted input, but a traversal entry would make
        # the lint read outside scripts/; refuse it rather than follow it.
        parts = Path(name).parts
        if Path(name).is_absolute() or ".." in parts or len(parts) != 1:
            print(f"manifest entry is not a plain scripts/ name: {name!r}",
                  file=sys.stderr)
            raise SystemExit(2)
        if name in seen:
            print(f"manifest lists {name!r} twice", file=sys.stderr)
            raise SystemExit(2)
        seen.add(name)
    return names


def _show_diff(name: str, ours: bytes, theirs: bytes) -> None:
    ours_lines = ours.decode("utf-8", errors="replace").splitlines()
    theirs_lines = theirs.decode("utf-8", errors="replace").splitlines()
    diff = list(
        difflib.unified_diff(
            ours_lines,
            theirs_lines,
            fromfile=f"active-rpc/scripts/{name}",
            tofile=f"active-infinity/scripts/{name}",
            lineterm="",
        )
    )
    if not diff:
        # Byte-identical text cannot reach here; a no-text diff means the
        # bytes differ outside the decoded text (line endings or encoding).
        print("  (bytes differ outside the decoded text: "
              "line endings or encoding)")
        return
    shown = diff[:MAX_DIFF_LINES]
    for line in shown:
        print(f"  {line}")
    if len(diff) > len(shown):
        print(f"  ... ({len(diff) - len(shown)} more diff lines)")


def main() -> int:
    here = Path(__file__).resolve()
    default_root = here.parent.parent
    parser = argparse.ArgumentParser(
        description="Fail when a script shared with active-infinity "
        "has diverged between the repos (TEST-12)."
    )
    parser.add_argument(
        "--other-repo",
        default=None,
        help="active-infinity checkout to compare against "
        "(default: sibling ../active-infinity next to --root)",
    )
    parser.add_argument(
        "--root",
        default=str(default_root),
        help="active-rpc checkout root (default: derived from this file)",
    )
    parser.add_argument(
        "--manifest",
        default="scripts/shared-scripts.txt",
        help="manifest of shared scripts, relative to --root "
        "(default: scripts/shared-scripts.txt)",
    )
    args = parser.parse_args()

    root = Path(args.root)
    # The default other-repo is the sibling of the *effective* root, not
    # of this file: --root may point at a checkout elsewhere (fixture
    # trees, or the audit layout), and the sibling must follow it.
    other = (
        Path(args.other_repo)
        if args.other_repo
        else root.parent / "active-infinity"
    )
    if not other.is_dir():
        print(
            "active-infinity checkout not found: "
            f"{other}\n"
            "Check it out next to this repo, or pass --other-repo "
            "with its path.",
            file=sys.stderr,
        )
        return 2
    manifest = Path(args.manifest)
    if not manifest.is_absolute():
        manifest = root / manifest
    names = _load_manifest(manifest)

    failures = 0
    for name in names:
        ours_path = root / "scripts" / name
        theirs_path = other / "scripts" / name
        if not ours_path.is_file():
            print(f"DIVERGES {name}: missing in this repo ({ours_path})")
            failures += 1
            continue
        if not theirs_path.is_file():
            print(
                f"DIVERGES {name}: missing in active-infinity "
                f"({theirs_path})"
            )
            failures += 1
            continue
        ours = ours_path.read_bytes()
        theirs = theirs_path.read_bytes()
        if ours == theirs:
            print(f"ok       {name} ({_sha256(ours)[:16]})")
            continue
        failures += 1
        print(
            f"DIVERGES {name}:\n"
            f"  active-rpc:      sha256 {_sha256(ours)}\n"
            f"  active-infinity: sha256 {_sha256(theirs)}"
        )
        _show_diff(name, ours, theirs)

    if failures:
        print(
            f"shared scripts diverge: {failures} of {len(names)} file(s) "
            "differ between active-rpc and active-infinity.\n"
            "Mirror the change in the other repo (same change, both "
            "repos) and re-run this check.",
            file=sys.stderr,
        )
        return 1
    print(
        f"shared scripts agree: {len(names)} file(s) byte-identical "
        f"with {other}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
