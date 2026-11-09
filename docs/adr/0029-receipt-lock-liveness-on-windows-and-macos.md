# ADR 0029 — Receipt-lock pid liveness on Windows and macOS

**Status:** Accepted 2026-11-09 (XPL-RPC-02).

## Context

The receipt log's steal rule (`lock_is_live`, `src/receipts.rs`) honours a
lock past the 120-second stale ceiling while the pid it names is alive, up
to the 20-minute grace (`LOCK_LIVE_GRACE_MS`). On Linux the liveness probe
is a `/proc/{pid}` existence check. On every other platform
`process_is_alive` returned `false` unconditionally, so on Windows and
macOS a live holder's lock was stealable 130 seconds in — two writers could
append interleaved chains into one log, corrupting the audit evidence. The
W6 verification probe reproduced it on Windows: a lock naming a live pid,
aged 130 seconds, was stolen and the append returned `Ok(())`, where Linux
would have refused until the grace.

The same gap is half of XPL-RPC-12 (`process_is_alive` no-op off Linux);
the other half of that finding (`sync_parent` unix-only, the
signalled-child guard in `src/tool.rs`) is untouched here and stays open
under XPL-RPC-12.

## Decision

Implement the probe the audit recommended — `OpenProcess` plus an exit-code
check on Windows, `kill(pid, 0)` on macOS — with the `unsafe` confined to
a one-function helper crate instead of a carve-out in this crate:

- New crate `process-liveness/` (package `active-rpc-liveness`, v0.1.0,
  `publish = false`), whose whole public API is one safe function,
  `process_is_alive(pid: u32) -> bool`. The root crate depends on it only
  under `cfg(any(windows, target_os = "macos"))`; Linux keeps the `/proc`
  check, and any other platform keeps the age rule as the whole test.
- Windows (`OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, pid)` +
  `GetExitCodeProcess`): a handle that opens and reports `STILL_ACTIVE`
  is a live process; any other exit code is a process that already exited.
  `OpenProcess` failing with access denied means a live process the caller
  may not inspect (a Protected Process, a SYSTEM process from a non-admin
  caller), so it reports alive — matching the Linux `/proc` check, which
  sees every pid regardless of owner. Any other failure means no such
  process. The handle is closed on every path.
- macOS (`kill(pid, 0)`): success is alive, `ESRCH` is dead, `EPERM` is a
  live process owned by someone else, and any other error is not a live
  process. Pid 0 is refused outright (`kill(0, 0)` would test the caller's
  whole process group), and a `u32` pid past `i32::MAX` is refused before
  the cast (it would wrap to a negative `pid_t`, and `kill(-1, 0)` signals
  every process the caller may signal).

Alternatives considered and rejected:

- **Weakening the crate policy** (`#![forbid(unsafe_code)]` to `deny` plus
  a scoped `#[allow(unsafe_code)]` on one function): `forbid` cannot be
  overridden by `allow`, so the change would have weakened the crate-wide
  invariant — the same invariant the shm transport and ADR-0003 cite as a
  design choice, and the reason the job-object fix (XPL-RPC-04) is recorded
  as a residual rather than a carve-out. The helper crate preserves the
  invariant exactly: `active-rpc` still forbids `unsafe` everywhere.
- **Spawning `tasklist`**: the only std-only Windows probe. It would
  reintroduce the ARPC-004 hole class — the binary would be found through
  the process environment (`PATH`, or a `SystemRoot`-derived path), so a
  poisoned environment chooses the binary that runs on every steal
  judgement — and it would make a security decision depend on parsing
  `tasklist` output. The FFI call is exact, has no subprocess, and takes
  no environment input.
- **Shortening the Linux grace to 120 seconds** (the audit's fallback): it
  makes Linux as weak as Windows instead of fixing Windows. Rejected.
- **A new registry dependency** (e.g. `sysinfo`): not in the lockfile, so
  it would need a network fetch and would pull a large graph for one call.
  `windows-sys 0.61.2` and `libc 0.2` are already in the lockfile as
  transitive dependencies; the helper adds no new registry crate to the
  graph (verified: the lockfile gains only the `active-rpc-liveness`
  entry).

## Consequences

- A lock naming a live pid is honoured until the 20-minute grace on
  Windows, macOS, and Linux alike. The steal rule, the reader's
  `writer_active`, and the grace bound are unchanged; only the probe
  behind them is now real on all three platforms.
- A lock naming a dead pid is still stolen past the ceiling, on every
  platform — a liveness fix that never reports dead would wedge the log.
- Residuals (bounded, documented in the helper crate): a process that
  exits with code 259 is misread as live until the grace expires (the same
  bounded residual as a reused pid on Linux); a planted lock naming a live
  pid still blocks the log until the grace, exactly as on Linux — the grace
  is what bounds it.
- The macOS leg is compile-verified but not executed: no macOS host is
  available to this team, so the `kill(pid, 0)` branch has not run. It has
  been type-checked with `cargo check --target x86_64-apple-darwin
  --all-targets` (the target std was installed for this check with `rustup
  target add x86_64-apple-darwin`); it is 20 lines, uses only `libc::kill`
  and `errno` values, and is the first `target_os = "macos"` branch in the
  repo. Execution on macOS awaits the macOS CI job the audit recommends
  (XPL-01).
- ADR-0028's residual line ("the lock's liveness check still degrades to
  an age rule on Windows (XPL-RPC-02)") is closed by this decision.
  XPL-RPC-12 stays open for its `sync_parent` and `tool.rs` halves.
