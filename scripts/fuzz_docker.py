"""Run every cargo-fuzz target in a Linux container.

cargo-fuzz does not launch on Windows MSVC (libFuzzer reports
STATUS_DLL_NOT_FOUND), so the reproducible lane is Docker. The image carries
clang, a nightly toolchain and cargo-fuzz; the repository is mounted read-write
so cargo-fuzz can grow the committed corpus.

Usage:
    python scripts/fuzz_docker.py --build
    python scripts/fuzz_docker.py --all --runs 20000
    python scripts/fuzz_docker.py --target fuzz_arp1_frame --runs 2000
    python scripts/fuzz_docker.py --list
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

IMAGE = "active-fuzz:1.88"
TARGETS = [
    "fuzz_arp1_frame",
    "fuzz_capability_lifecycle",
    "fuzz_promise_graph",
    "fuzz_budget_matrix",
    "fuzz_tool_mcp",
    "fuzz_tool_http",
    "fuzz_tool_process",
    "fuzz_channel_cap_transfer",
    "fuzz_transport_framing",
]


def run(
    cmd: list[str], cwd: Path, timeout: int | None = None
) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--build", action="store_true", help="build the fuzz image")
    parser.add_argument("--all", action="store_true", help="run every target")
    parser.add_argument("--target", action="append", default=[], help="run one target")
    parser.add_argument(
        "--runs", type=int, default=20000, help="libFuzzer -runs budget"
    )
    parser.add_argument("--list", action="store_true")
    parser.add_argument("--timeout", type=int, default=1800, help="seconds per target")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent

    if args.list:
        print(json.dumps(TARGETS, indent=2))
        return 0

    if args.build:
        built = run(
            [
                "docker",
                "build",
                "-t",
                IMAGE,
                "-f",
                str(root / "docker" / "fuzz.Dockerfile"),
                str(root / "docker"),
            ],
            root,
        )
        if built.returncode != 0:
            print(built.stdout + built.stderr, file=sys.stderr)
            return 1
        print(f"built {IMAGE}")

    selected = list(TARGETS) if args.all else args.target
    if not selected:
        parser.error("choose --all, --build or --target")
    unknown = [target for target in selected if target not in TARGETS]
    if unknown:
        parser.error(f"unknown targets: {', '.join(unknown)}")

    failures: list[str] = []
    for target in selected:
        print(f"== {target} ({args.runs} runs) ==")
        command = (
            f"cargo +nightly fuzz build {target} && "
            f"cargo +nightly fuzz run {target} -- -runs={args.runs} -print_final_stats=1"
        )
        result = run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{root}:/work",
                "-w",
                "/work/fuzz",
                IMAGE,
                "bash",
                "-c",
                "export PATH=/usr/local/cargo/bin:$PATH; " + command,
            ],
            root,
            timeout=args.timeout,
        )
        output = result.stdout + result.stderr
        if result.returncode != 0:
            failures.append(target)
            print(output[-6000:])
            print(f"FAIL {target}")
        else:
            tail = [
                line
                for line in output.splitlines()
                if "stat::" in line or "Done" in line
            ]
            print("\n".join(tail[-12:]))
            print(f"ok   {target}")

    print()
    if failures:
        print(f"{len(failures)} target(s) failed: {', '.join(failures)}")
        return 1
    print(f"all {len(selected)} targets completed without a crash")
    return 0


if __name__ == "__main__":
    sys.exit(main())
