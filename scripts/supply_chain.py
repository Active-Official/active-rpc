#!/usr/bin/env python3
"""Supply-chain gate: `cargo deny check` + `cargo audit` for the root AND
every sub-crate (R2-SUPPLY-02).

The repo is not a Cargo workspace: the root, cli, control-plane, and fuzz
crates are standalone packages, each with its own Cargo.lock, and the root
deny.toml / audit.toml exist only at the repo root. A root-only
`cargo deny check` + `cargo audit` (what CI used to run) never sees the
sub-crates' graphs, so a banned crate, an unapproved license, or a new
advisory in a sub-crate passed the gate silently. This script closes
that hole:

* For each crate it builds the deny config as the root deny.toml PLUS
  that crate's overlay (scripts/supply-chain/deny-<crate>.toml), written
  to a temporary file. The config is generated from the root file on
  every run, so a stale copy can never silently re-open the drift, and
  nothing is written into the sub-crate directories. The overlays are
  pure appends (`[[licenses.exceptions]]` blocks), so they extend the
  root policy without redefining any of its tables.
* It runs `cargo deny check` (all four checks) with that config against
  the crate's manifest, and `cargo audit --deny warnings` against the
  crate's lockfile, with the one accepted advisory
  (RUSTSEC-2024-0449, unsafe-libyaml, not in the parsing path; see
  deny.toml / audit.toml) ignored in both tools.

The scoped exceptions live in the overlays and in the root deny.toml
(sha1: `wrappers = ["axum", "tungstenite"]` on the deny entry -- RFC
6455 WebSocket handshake hash, protocol-mandated, only those two crates
may bring it in). Each exception names the exact crate version and
license, with its rationale in the file that declares it; a version
bump fails the gate until the new version is reviewed.

Usage: python3 scripts/supply_chain.py
Exit 0 iff every crate passes both checks. On failure the failing
tool's output and the generated config are printed, so a CI failure is
self-diagnosing. Requires cargo-deny and cargo-audit on PATH (CI
installs pinned versions; the script also falls back to ~/.cargo/bin).
"""

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DENY_CONFIG = ROOT / "deny.toml"
IGNORED_ADVISORY = "RUSTSEC-2024-0449"

# (label, manifest relative to ROOT, overlay relative to ROOT or None)
CRATES = [
    ("root", "Cargo.toml", None),
    ("cli", "cli/active-rpc-cli/Cargo.toml", None),
    ("control-plane", "control-plane/Cargo.toml",
     "scripts/supply-chain/deny-control-plane.toml"),
    ("fuzz", "fuzz/Cargo.toml", "scripts/supply-chain/deny-fuzz.toml"),
]


def _ascii(text):
    """cargo-deny draws box-drawing trees; the Windows console is cp1252
    and cannot print them. Sanitise so the script works on every host."""
    return text.encode("ascii", "replace").decode()


def _find_tool(name):
    path = shutil.which(name)
    if path:
        return path
    home_bin = Path.home() / ".cargo" / "bin"
    candidate = home_bin / (name + ".exe" if os.name == "nt" else name)
    if candidate.is_file():
        return str(candidate)
    raise SystemExit(f"supply_chain: {name} not found on PATH or in "
                     f"{home_bin}; install it first")


def _run(cmd, cwd):
    result = subprocess.run(cmd, cwd=str(cwd), capture_output=True,
                            text=True, encoding="utf-8", errors="replace")
    return result.returncode, _ascii(result.stdout + result.stderr)


def _deny_config(overlay):
    """Root deny.toml plus the crate overlay, as one generated document."""
    text = DENY_CONFIG.read_text(encoding="utf-8")
    if overlay is not None:
        text += "\n" + overlay.read_text(encoding="utf-8")
    return text


def main():
    deny = _find_tool("cargo-deny")
    audit = _find_tool("cargo-audit")
    if not DENY_CONFIG.is_file():
        raise SystemExit(f"supply_chain: root config missing: {DENY_CONFIG}")

    failures = []
    for label, manifest_rel, overlay_rel in CRATES:
        manifest = ROOT / manifest_rel
        lock = manifest.parent / "Cargo.lock"
        overlay = ROOT / overlay_rel if overlay_rel else None
        for path, what in ((manifest, "manifest"), (lock, "lockfile")):
            if not path.is_file():
                raise SystemExit(f"supply_chain: {label} {what} missing: "
                                 f"{path}")
        if overlay is not None and not overlay.is_file():
            raise SystemExit(f"supply_chain: {label} overlay missing: "
                             f"{overlay}")

        config_text = _deny_config(overlay)
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".toml",
                                          delete=False, encoding="utf-8")
        try:
            tmp.write(config_text)
            tmp.close()
            deny_rc, deny_out = _run(
                [deny, "--manifest-path", str(manifest),
                 "--config", tmp.name, "check"], ROOT)
            audit_rc, audit_out = _run(
                [audit, "audit", "--deny", "warnings",
                 "--ignore", IGNORED_ADVISORY, "--file", str(lock)], ROOT)
        finally:
            os.unlink(tmp.name)

        status = "ok" if deny_rc == 0 and audit_rc == 0 else "FAIL"
        print(f"[{status}] {label}: "
              f"cargo deny exit={deny_rc}, cargo audit exit={audit_rc}")
        if deny_rc != 0:
            print(f"--- cargo deny output ({label}) ---")
            print(deny_out)
            print(f"--- generated deny config ({label}) ---")
            print(_ascii(config_text))
            failures.append(f"{label}: cargo deny exit={deny_rc}")
        if audit_rc != 0:
            print(f"--- cargo audit output ({label}) ---")
            print(audit_out)
            failures.append(f"{label}: cargo audit exit={audit_rc}")

    print()
    if failures:
        print("SUPPLY-CHAIN GATE FAILED:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print("SUPPLY-CHAIN GATE OK: all 4 crates pass cargo deny + cargo audit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
