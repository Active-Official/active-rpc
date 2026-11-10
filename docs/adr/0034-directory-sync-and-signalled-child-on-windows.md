# ADR 0034 — Parent-directory sync and the signalled-child guard on Windows

**Status:** Accepted 2026-11-09 (XPL-RPC-12).

## Context

XPL-RPC-12 names three places where the receipt log and the tool adapter
degrade off Linux. One leg — `process_is_alive` — was already closed by
XPL-RPC-02 (ADR-0029), which implemented the Windows `OpenProcess` and
macOS `kill(pid, 0)` probes in the `active-rpc-liveness` helper crate; this
ADR records the proof that the leg is closed and fixes the other two.

- **`sync_parent` was a no-op on Windows.** `src/receipts.rs` flushed
  the parent directory with `File::open(dir)` + `sync_all()` under
  `#[cfg(unix)]` and did nothing under `#[cfg(not(unix))]`, and the CLI's
  replay dump (`cli/active-rpc-cli/src/main.rs`) had the same unix-only
  block. The comment on `install_staged` conceded the durability
  guarantee was a unix one (L-6; round 12, F6). A receipt log created on
  Windows could therefore return `Ok` for a name a power loss forgets:
  the file's bytes were flushed (`file.sync_all()` maps to
  `FlushFileBuffers` on Windows), but the directory entry was not.
- **The signalled-child guard was dead code on Windows.**
  `src/tool.rs` reports a child with no exit code as
  `process/signalled` (a withheld reply, round 44, M-2). On Windows
  `ExitStatus::code()` always yields `Some` — `TerminateProcess` always
  supplies a code — so the `None` arm could never fire there, and a
  child terminated by another process was reported with its termination
  code as an ordinary status instead.

## Decision

- **A real directory flush on Windows, in a helper crate.** New crate
  `dir-sync/` (package `active-rpc-dir-sync`, v0.1.0, `publish =
  false`), whose whole public API is one safe function,
  `sync_parent_dir(path: &Path) -> bool`: it syncs the parent directory
  of the file named (a bare file name syncs the current directory) and
  reports whether the flush succeeded. The root crate and the CLI both
  depend on it unconditionally, and both call sites — `sync_parent` in
  `src/receipts.rs` and the replay dump in
  `cli/active-rpc-cli/src/main.rs` — are one call each, with the same
  best-effort semantics as before (a failed flush is ignored; the file's
  own `sync_all` is what orders the bytes). The `install_staged` comment
  is updated: the durability guarantee is no longer a unix one.
- **Windows (`CreateFileW` + `FlushFileBuffers`):** the parent directory
  is opened with `FILE_FLAG_BACKUP_SEMANTICS` (without which a directory
  cannot be opened at all), shared for read, write and delete, opened
  with `OPEN_EXISTING` so a missing parent fails instead of creating
  anything, and flushed with `FlushFileBuffers`. Two facts found by
  probing, not by reading, are recorded in the crate because they are
  easy to get wrong:
  - `windows-sys` 0.61 provides no `GENERIC_READ` constant (the
    file-specific name is `FILE_GENERIC_READ`), and gates `CreateFileW`
    on the `Win32_Security` feature (its signature takes a
    `SECURITY_ATTRIBUTES` pointer), so the helper enables
    `Win32_Security` alongside `Win32_Foundation` and
    `Win32_Storage_FileSystem`.
  - A directory handle opened read-only does **not** flush: on this
    machine `FlushFileBuffers` on a `FILE_GENERIC_READ` handle fails
    with `ERROR_ACCESS_DENIED` (error 5), even though the open
    succeeds. The handle is therefore opened with
    `FILE_GENERIC_READ | FILE_GENERIC_WRITE`. (The SQLite shape —
    read-only — was the first attempt; the probe disproved it here.)
  The handle is closed on every path. A missing parent reports `false`.
- **Unix is unchanged in behaviour:** the helper does the same
  `File::open(parent)` + `sync_all()` the two call sites did inline, so
  the Unix leg is a move, not a change. macOS takes the Unix branch.
- **The `process_is_alive` leg is closed by XPL-RPC-02, proven here:**
  the two Linux-gated integration tests the audit named —
  `a_lock_whose_pid_is_alive_is_not_stolen` and
  `a_live_pid_lock_inside_the_grace_is_not_stolen`
  (`tests/receipt_round5_tests.rs`) — are ungated and pass on Windows,
  and the stale "the liveness check exists only where the kernel exposes
  another process cheaply (`/proc`)" comment is corrected. No product
  code changes for this leg; the fix landed under XPL-RPC-02.
- **The signalled-child guard is unix-only by construction.** The
  `None` arm in `src/tool.rs` is gated `#[cfg(unix)]`; on non-Unix the
  match keeps an explicit `None => -1` arm so it stays exhaustive, with
  a comment stating it is unreachable by construction and `-1` is never
  reported. No behaviour changes on any platform: the guard fired only
  on Unix before, and fires only on Unix now. The Windows residual is
  documented, not hidden: an externally terminated child reports its
  termination code as an ordinary status, because Windows cannot tell a
  termination code from a code the child exited with itself — so the
  reply is not withheld for it. That residual is pinned by the Windows
  test `a_child_terminated_by_another_process_reports_its_exit_code`
  (`tests/tool_round43_tests.rs`), in which the child terminates itself
  with `taskkill` (TerminateProcess, code 1) and the reply carries
  status 1.

Alternatives considered and rejected:

- **Weakening the crate policy** (`#![forbid(unsafe_code)]` to `deny`
  plus a scoped `#[allow(unsafe_code)]`): rejected for the same reason
  as in ADR-0029 — `forbid` cannot be overridden by `allow`, and the
  helper crate preserves the invariant exactly.
- **Spawning a helper process to flush the directory** (e.g. a
  `powershell` or `fsutil` call): rejected — it would make a durability
  decision depend on finding a binary through the process environment
  (the ARPC-004 hole class) and on parsing its output, where the FFI
  call is exact and takes no environment input.
- **A working signalled-child guard on Windows** (e.g. treating a
  distinctive termination code as a signal): rejected — no termination
  code is distinctive on Windows; `taskkill` terminates with code 1,
  which a child can also exit with itself, so any code-based rule would
  misclassify ordinary failures as withheld replies. Gating the guard
  and documenting the residual is the honest shape.
- **A new registry dependency** (e.g. `fs2` or `fdatasync` wrappers):
  not in the lockfile, so it would need a network fetch for one call.
  `windows-sys 0.61.2` is already in the lockfile as a transitive
  dependency; the helper adds no new registry crate to the graph
  (verified: the lockfile gains only the `active-rpc-dir-sync` entry).

## Consequences

- A receipt log created on Windows is durable in the same sense as on
  Unix: the directory entry is flushed, not just the file's bytes. The
  CLI's replay dump has the same guarantee.
- A lock naming a live pid is honoured until the grace on Windows,
  macOS, and Linux alike — proven by the ungated tests, not just by the
  helper's unit tests.
- The signalled-child guard is explicitly unix-only; the Windows
  behaviour (termination code as an ordinary status, reply not
  withheld) is pinned by a test, so a future change cannot silently
  reclassify it.
- Residuals (bounded, documented in the helper crate and in `tool.rs`):
  no test can prove crash durability short of pulling the plug — what
  the tests prove is that the documented Windows equivalent is invoked
  and reports success, the same guarantee level as the Unix `sync_all`
  it mirrors; a parent directory the caller cannot open for writing
  reports `false` and is ignored (the call sites only sync directories
  they just wrote to, so this is not reachable in practice); an
  externally terminated child on Windows is not a withheld reply (see
  above).
- ADR-0029's closing line ("XPL-RPC-12 stays open for its `sync_parent`
  and `tool.rs` halves") is closed by this decision. The `O_NOFOLLOW` /
  check-then-open half of XPL-RPC-12 belongs to XPL-RPC-01 and was fixed
  there (commit `e485032`); it is not re-decided here.
- The macOS legs are compile-verified but not executed: no macOS host is
  available to this team, so the Unix branch of the helper has not run
  on macOS and the ungated lock tests have not run there. Both have been
  type-checked with `cargo check --target x86_64-apple-darwin
  --all-targets`; the helper's Unix branch is the same
  `File::open` + `sync_all` that already ran on Linux, and the tests
  use only `std` file-time calls. Execution on macOS awaits the macOS CI
  job the audit recommends (XPL-01).
