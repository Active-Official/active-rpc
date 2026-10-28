#!/usr/bin/env python3
"""Prove that each security-critical check fails when its guard is removed.

A test that passes on a broken build proves nothing. This runner copies the
working tree (including uncommitted changes), confirms every mapped check
passes there, then applies one precise source mutation per control, runs the
mapped check, and requires a real test failure (not a compile error). The copy
is removed afterwards, so the working tree is never touched.

Usage:
    python scripts/negative_controls.py --check
    python scripts/negative_controls.py --only I-3-redaction --keep
    python scripts/negative_controls.py --list
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CONTROLS = [
    {
        "id": "I-3-redaction",
        "invariant": "I-3",
        "file": "src/domain.rs",
        "find": "        if is_secret {\n            *redacted.node_mut(id)? = Inode::Str(security::SECRET_MARKER.to_string());\n        }\n",
        "replace": "        if false {\n            *redacted.node_mut(id)? = Inode::Str(security::SECRET_MARKER.to_string());\n        }\n",
        "suite": "redteam_tests",
        "test": "review_module_payloads_are_redacted",
        "why": "Module payload redaction is disabled; the subgraph response carries the canary.",
    },
    {
        "id": "I-4-secret",
        "invariant": "I-4",
        "file": "src/kernel.rs",
        "find": '        getrandom::fill(&mut seed).expect("the operating system CSPRNG must be available");\n',
        "replace": "        let _ = &mut seed;\n",
        "suite": "redteam_tests",
        "test": "review_agent_secrets_are_random",
        "why": "Every agent gets the same all-zero secret, so minted capability ids collide.",
    },
    {
        "id": "I-4-debug",
        "invariant": "I-4",
        "file": "src/cap.rs",
        "find": '        write!(f, "CapId({})", self.correlation_id())\n',
        "replace": '        write!(f, "CapId({})", self.hex())\n',
        "suite": "unit_tests",
        "test": "capability_debug_does_not_print_raw_bits",
        "why": "CapId Debug prints the raw 128-bit authority, so any logged event leaks it.",
    },
    {
        "id": "I-5-attenuation",
        "invariant": "I-5",
        "file": "src/cap.rs",
        "find": "        if !child.methods.is_subset(&self.methods) {\n",
        "replace": "        if false {\n",
        "suite": "unit_tests",
        "test": "attenuation_narrows_and_never_widens",
        "why": "A child may add methods its parent never held; escalation is no longer refused.",
    },
    {
        "id": "I-6-dispatch",
        "invariant": "I-6",
        "file": "src/kernel.rs",
        "find": "                    Some(record) if record.revoked => Some(Error::Revoked(cap_token(record.id))),\n",
        "replace": "                    Some(record) if false => Some(Error::Revoked(cap_token(record.id))),\n",
        "suite": "redteam_tests",
        "test": "review_revocation_after_queueing_prevents_invocation",
        "why": "The dispatch loop no longer re-checks revocation, so a revoked queued call reaches the provider.",
    },
    {
        "id": "I-8-shm",
        "invariant": "I-8",
        "file": "src/transport/shm.rs",
        "find": "            let tail_start = state.tail as usize % state.capacity;\n",
        "replace": "            let tail_start = state.head as usize % state.capacity;\n",
        "suite": "unit_tests",
        "test": "shared_memory_compaction_survives_a_wrapped_ring",
        "why": "Compaction reads from the head offset instead of the tail, so a wrapped ring panics.",
    },
    {
        "id": "I-8-bytes",
        "invariant": "I-8",
        "edits": [
            {
                "file": "src/kernel.rs",
                "find": '        if call_bytes > effective.max_bytes {\n            return Err(Error::BudgetExceeded("byte"));\n        }\n',
                "replace": '        if false {\n            return Err(Error::BudgetExceeded("byte"));\n        }\n',
            },
            {
                "file": "src/kernel.rs",
                "find": "        meter.charge(call_bytes)?;\n",
                "replace": "        meter.charge(0)?;\n",
            },
        ],
        "suite": "redteam_tests",
        "test": "review_byte_budget_is_charged",
        "why": "Both the per-call ceiling and the meter charge are removed, so the byte budget never fires.",
    },
    {
        "id": "I-10-trailing",
        "invariant": "I-10",
        "file": "src/wire.rs",
        "find": '        if cursor != bytes.len() {\n            return Err(Error::Wire("trailing bytes"));\n        }\n',
        "replace": '        if false {\n            return Err(Error::Wire("trailing bytes"));\n        }\n',
        "suite": "unit_tests",
        "test": "wire_rejects_malformed_envelopes",
        "why": "An envelope with trailing bytes is accepted, so the malformed-frame case passes.",
    },
    {
        "id": "C-1-settlement",
        "invariant": "C-1",
        "file": "src/promise.rs",
        "find": "    pub fn resolve(&mut self, value: Value) -> Result<()> {\n        match self.state {\n            PromiseState::Pending => {\n                self.state = PromiseState::Resolved(value);\n                Ok(())\n            }\n            _ => Err(Error::PromiseAlreadyResolved(self.id.0)),\n        }\n    }\n",
        "replace": "    pub fn resolve(&mut self, value: Value) -> Result<()> {\n        self.state = PromiseState::Resolved(value);\n        Ok(())\n    }\n",
        "suite": "unit_tests",
        "test": "promise_can_be_cancelled_or_resolved_once",
        "why": "A promise accepts a second settlement, so the second resolve no longer errors.",
    },
]


def run(
    cmd: list[str], cwd: Path, env: dict[str, str], timeout: int = 600
) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout
    )


def run_test(
    tree: Path, env: dict[str, str], control: dict
) -> subprocess.CompletedProcess:
    return run(
        [
            "cargo",
            "test",
            "--locked",
            "--all-features",
            "--test",
            control["suite"],
            "--",
            "--exact",
            control["test"],
        ],
        tree,
        env,
    )


def failure_names(output: str) -> str:
    marker = "failures:"
    if marker not in output:
        return ""
    return output.split(marker, 1)[1]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="run every control")
    parser.add_argument("--only", help="run one control by id")
    parser.add_argument("--list", action="store_true", help="list controls and exit")
    parser.add_argument(
        "--keep", action="store_true", help="keep the worktree for debugging"
    )
    args = parser.parse_args()

    if args.list:
        for control in CONTROLS:
            print(f"{control['id']:18} {control['invariant']:5} {control['file']}")
        return 0

    selected = CONTROLS
    if args.only:
        selected = [c for c in CONTROLS if c["id"] == args.only]
        if not selected:
            print(f"unknown control: {args.only}", file=sys.stderr)
            return 2

    root = Path(__file__).resolve().parent.parent
    base = Path(tempfile.mkdtemp(prefix="active-negative-"))
    tree = base / "tree"
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(base / "target")
    env["CARGO_TERM_COLOR"] = "never"

    failures: list[str] = []
    try:
        # Copy the working tree, including uncommitted changes. A control must
        # test the code under review, not the last commit; a git worktree would
        # silently run the old tree and turn a new test into a vacuous pass.
        shutil.copytree(
            root,
            tree,
            ignore=shutil.ignore_patterns(
                ".git", "target", "fuzz", ".scratch", "__pycache__"
            ),
            symlinks=True,
        )

        print("== baseline: the unmutated checks must pass ==")
        for control in selected:
            result = run_test(tree, env, control)
            if result.returncode != 0:
                failures.append(
                    f"{control['id']}: baseline failed on the unmutated tree"
                )
                print(f"FAIL {control['id']}: baseline failed")
                print(result.stdout[-2000:])
            else:
                print(f"ok   {control['id']}: baseline passes")

        print("== controls: the mutated checks must fail ==")
        for control in selected:
            edits = control.get("edits")
            if edits is None:
                edits = [
                    {
                        "file": control["file"],
                        "find": control["find"],
                        "replace": control["replace"],
                    }
                ]
            originals: dict[Path, str] = {}
            applied = True
            for edit in edits:
                path = tree / edit["file"]
                if path not in originals:
                    originals[path] = path.read_text(encoding="utf-8")
                current = path.read_text(encoding="utf-8")
                occurrences = current.count(edit["find"])
                if occurrences != 1:
                    failures.append(
                        f"{control['id']}: mutation anchor occurs {occurrences} times in {edit['file']}"
                    )
                    print(
                        f"FAIL {control['id']}: anchor occurs {occurrences} times in {edit['file']}"
                    )
                    applied = False
                    break
                path.write_text(
                    current.replace(edit["find"], edit["replace"], 1),
                    encoding="utf-8",
                    newline="\n",
                )
            if not applied:
                for path, original in originals.items():
                    path.write_text(original, encoding="utf-8", newline="\n")
                continue
            try:
                result = run_test(tree, env, control)
            finally:
                for path, original in originals.items():
                    path.write_text(original, encoding="utf-8", newline="\n")
            output = result.stdout + result.stderr
            if result.returncode == 0:
                failures.append(
                    f"{control['id']}: the check still passed on a broken build"
                )
                print(f"FAIL {control['id']}: check still passed")
                continue
            if "error[E" in output or "could not compile" in output:
                failures.append(f"{control['id']}: the mutation did not compile")
                print(f"FAIL {control['id']}: mutation did not compile")
                print(output[-2000:])
                continue
            if "test result: FAILED" not in output:
                failures.append(
                    f"{control['id']}: the mapped test did not run to a failure"
                )
                print(f"FAIL {control['id']}: no test failure in output")
                print(output[-2000:])
                continue
            if control["test"] not in failure_names(output):
                failures.append(f"{control['id']}: a different test failed")
                print(f"FAIL {control['id']}: wrong test in the failure list")
                continue
            print(f"PASS {control['id']}: {control['test']} failed as required")

        print()
        if failures:
            print(f"{len(failures)} control(s) failed:")
            for failure in failures:
                print(f"  - {failure}")
            return 1
        print(f"all {len(selected)} negative controls behaved as required")
        return 0
    finally:
        if args.keep:
            print(f"tree kept at {tree}")
        else:
            shutil.rmtree(base, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
