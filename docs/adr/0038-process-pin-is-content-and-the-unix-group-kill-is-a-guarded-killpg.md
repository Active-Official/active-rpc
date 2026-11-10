# ADR 0038 — Process pinning is content, not just path; the Unix group kill is a guarded `killpg`

**Status:** Accepted 2026-11-10 (RPC-43).

## Context

Round 1, R-08 M6 (AUDIT-REPORT.md), verified CONFIRMED by W2 at both
89b6404 and 7702ece: `pin_program` canonicalises the program path but
never hashes the binary, and `kill_process_tree` signals `-<pid>`
through an external `/bin/kill`.

- **The pin is path-only.** A `LocalProcess` pins its program by
  canonical path at construction and spawns that path at every invoke.
  W2's reproduction compiles a tiny exe printing `PIN-VERSION-1`, pins
  it, invokes it (prints `PIN-VERSION-1`), replaces the file in place
  with a recompiled `PIN-VERSION-2` binary, and invokes the SAME
  `LocalProcess` again — it runs the new binary (`PIN-VERSION-2`). No
  hash is recorded at construction and none is re-verified before
  spawn. The canonical path, the inode and the mode all survive an
  in-place replacement, so only a content check can see it.
- **The Unix kill has a PID-reuse race.** `kill_process_tree` signals
  the negative pid — the process group the spawn created, which is the
  leader's pid — through an external `/bin/kill`. A pid is only unique
  while its owner lives: a leader that exited long before the kill may
  have had its pid reused as a new process-group leader, and the
  signal then takes an unrelated group down with it. Low probability,
  real consequence. The same external-binary shape served the
  single-pid kill in `kill_pipe_holders`.

The fix is intentionally behaviour-changing in two narrow ways: a
program whose bytes changed since construction is now refused at
spawn instead of run, and a dead leader's group is signalled only
when it is still provably ours. Both changes must be announced, not
slipped in — hence this ADR and the migration note.

## Decision

- **The pin is the content, not just the path.** `pin_program` now
  returns the canonical path together with the BLAKE3 digest of the
  file's bytes at pin time (streamed, so the binary's size does not
  bound memory). `LocalProcess` stores the digest and re-hashes before
  every spawn; `StdioTransport::spawn` re-hashes immediately before
  the exec, closing the gap the working-directory canonicalisation
  and the environment validation open between its pin and its spawn.
  A mismatch is a refusal (`rpc/provider` with
  `process/program-changed` for a process tool,
  `mcp/program-changed` for an MCP server), never a re-pin — a
  re-pin would bless whatever replaced the program. An unreadable
  file refuses the same way (`process/program-unreadable` /
  `mcp/program-unreadable` at spawn; `rpc/invalid-argument` at
  construction, where a program that canonicalises but cannot be read
  cannot be pinned at all — a directory used to pass construction
  and fail at spawn, and now fails at construction).
- **The Unix group kill is the `killpg` syscall, fired only when the
  group is still provably ours.** No external binary stands between
  the check and the signal: the `killpg`/`kill` calls live in the
  `active-rpc-process-tree` helper crate behind a safe API, in the
  same shape as the job object already there (this crate forbids
  `unsafe`). `process_group_still_ours` proves ownership before
  signalling: a leader that is still alive cannot have been reused
  (`try_wait` saying `None` proves the pid is still our child), and
  a dead leader's group is proven by a member still carrying the pgid
  in `/proc` on Linux — a pgid cannot be reused while a member
  carries it, and no member at all means the group is gone and there
  is nothing to kill. The single-pid kill in `kill_pipe_holders`
  takes the same treatment: the direct `kill` syscall, with the
  holder re-verified to still hold a target pipe write end
  immediately before the signal.
- **The Windows kill path is unchanged, and has no PID-reuse shape
  to fix.** The child runs in a job object (XPL-RPC-04): terminating
  the job ends the leader and every descendant atomically, by job
  handle, not by pid. The leader fallback (`Child::kill`) targets
  the exact process through the `Child` handle, which Windows
  process handles do not confuse across reuse. No `taskkill.exe`
  has been spawned on any path since XPL-RPC-04.

Alternatives considered and rejected:

- **Re-pinning silently on mismatch.** The check would be the same
  bug one step later (W2's fix assessment): a hash recorded once and
  never re-checked, or re-recorded whenever it differs, blesses
  whatever replaced the program. A mismatch is a refusal, and the
  operator re-creates the tool to run a new binary deliberately.
- **Hashing only at construction.** A digest recorded at construction
  and never re-read before spawn closes nothing: the replacement
  happens after construction, which is the finding. The re-hash
  before every spawn is the fix; the construction hash is the
  reference it compares against.
- **A partial hash (first N bytes).** An append-only or tail-only
  tamper would pass it. The full-file BLAKE3 stream costs one file
  read per spawn and is the honest check.
- **Closing the residual re-hash-to-exec window.** Between the
  re-hash and the `exec` a swap could still land. Closing it needs
  executing an open file descriptor (`fexecve`, or exec through
  `/proc/self/fd`), which `std::process::Command` does not offer.
  The window is one file read to the exec — microseconds, against
  the finding's window of the tool's whole lifetime — and it is
  recorded as a residual, not hidden.
- **A `/proc`-free ownership check on non-Linux Unix.** Without
  `/proc` there is nothing to verify a dead leader's group against,
  and closing it would need a process enumeration (the macOS `sysctl`
  path) that this host cannot test — an untestable FFI surface is not
  a fix. A dead leader's group is signalled there as before, with
  the residual recorded; a live leader is proven by `try_wait` on
  every Unix, which is the common timeout path.

## Consequences

- A program replaced in place after construction is refused at the
  next invoke with `rpc/provider` / `process/program-changed`
  (MCP: `mcp/program-changed`), before anything executes — pinned by
  the regression test, which runs the W2 reproduction (prints
  `PIN-VERSION-1`, replaces in place, invokes the same tool) on
  Windows and Linux, and by in-crate tests pinning the digest
  helper. A byte-identical rewrite still runs: the identity is
  content, not mtime or inode.
- A program that cannot be read is refused at construction with
  `rpc/invalid-argument` (`the program cannot be read`).
- A Unix timeout kill signals through `killpg`, and only a group
  proven still to be the child's own — pinned by Linux tests for
  the live leader, the dead leader with a living descendant (the
  signal must still fire), and the drained group (the signal must
  not fire), plus helper-crate tests for the syscalls themselves.
  The setsid-descendant kill (`kill_pipe_holders`) is unchanged in
  effect and now re-verifies each holder before signalling it.
- The residual windows are stated, not hidden: the re-hash-to-exec
  gap on every platform, and the dead-leader reuse race on
  non-Linux Unix (macOS), where there is no `/proc` to verify
  against. Both need a swap (or a full group death plus a pgid
  reuse) inside microseconds of the signal, against the finding's
  window of the tool's whole lifetime.
- Per `docs/hardening/COMPATIBILITY.md`, a security behaviour change
  is recorded in an ADR (this one) and the release notes; the
  release-notes line is owed at the next release.
