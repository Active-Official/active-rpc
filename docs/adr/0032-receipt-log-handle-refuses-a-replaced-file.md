# ADR 0032 — An open receipt-log handle refuses a replaced log file

**Status:** Accepted 2026-11-09 (F1-NF-07).

## Context

The receipt log's append path (`ReceiptLog::append_inner`,
`src/receipts.rs`) is built around a walk: the fast-path checks (length,
header, tail head, mtime, identity, content sample) are an optimisation,
and when any of them fails the writer re-reads the file and walks the
whole chain, adopting whatever the walk accepts. The walk accepts any
self-consistent chain — links verify, sequence continues, time runs
forwards. So an open handle adopts any self-consistent chain presented at
its path: replace the log file with a different, fully valid log of the
same length (same start sequence, different receipt contents) while a
handle is open, and the next append links onto the replacement chain. The
handle's history is then the replacement's history, with no error and no
record that a substitution happened. XPL-RPC-07's probe arm C observed
exactly that on native Windows (3 receipts read back, first receipt
`at_ms=11`, i.e. the replacement's history).

The property is platform-independent: on Linux the inode check only
forces the same re-walk, and under the audit's recommended identity fix
for XPL-RPC-07 an identity mismatch would also only force the re-walk.
RPC-14 does not cover it: RPC-14 is about the *read* path not verifying
per-receipt MACs, and its recommended fix would not stop the adoption —
the substitution is ratified at append time, and an older genuine backup
of the same log carries genuine MACs under the same key, so even a
MAC-checking walk passes on it. The finding is High: silent history
substitution in the audit trail, with the attacker capability (local file
write to the receipt directory) the same as XPL-RPC-07 and XPL-RPC-08.
It is High rather than Critical because the substitution requires a
complete, valid chain (recomputed links or a genuine backup), not a
one-byte edit.

## Decision

Refuse when the file identity changes — shape (b) of the two candidates
in the finding record — and do it before the walk, in `append_inner`'s
re-walk branch. When the handle's pinned identity (`LogState.identity`,
established by the first append's walk) is `Some` and the freshly read
file's identity is `Some` and the two differ, the append is refused with
`rpc/receipt` ("the receipt log file was replaced since this handle
opened it; reopen the log before appending") and the file is untouched.
The cached state is left intact, so if the original file returns the
handle appends again; the operator's remedy for a deliberate replacement
is to reopen the log.

The identity plumbing this needs already existed in part:

- On unix the identity is `(dev, ino)`, and `read_capped_with_identity`
  already reported it. The refusal is the only new behaviour there.
- On Windows the identity is the volume serial plus file index from
  `GetFileInformationByHandle` through the `active-rpc-file-identity`
  helper crate (XPL-RPC-08). `path_identity`, `identity_matches` and
  `same_identity` — which returned `true` unconditionally off unix, and
  `read_capped_with_identity` — which reported `None` off unix — now use
  the helper on Windows, mirroring the unix branches exactly. The
  `read_capped_with_identity` arm identifies the handle it read, not a
  second open, so the identity describes the bytes the walk would adopt.
  No manifest change: the helper is already a `cfg(windows)` dependency.
- `same_identity` now being real on Windows also makes `read_stable`
  fail closed when the file is swapped mid-read, exactly as on unix —
  the documented intent of that check ("a same-length replacement
  between the read and the stat is a different log").
- Where neither platform's identity exists, the residual stands: the
  append cannot pin a file it cannot identify, and a replacement is
  adopted by the walk. `create` already fails on those filesystems (the
  header install needs a hard link), so no working log exists there.

A survey of legitimate replace-while-open flows (recorded in full in the
F1-NF-07 record) shows nothing needs an open handle to survive a
replacement:

- **Restore does not exist for receipt logs.** No `ReceiptLog::restore`,
  no CLI `receipts restore`, no documentation of one. "Restore" in this
  codebase means capability-record restore, a different subsystem. An
  operator restoring a backup does it out of band; the contract after
  this decision is to stop the writer (or drop the handle), replace the
  file, and re-open.
- **Repair truncates the same file in place.** `ReceiptLog::repair` (and
  `repair_tail`, which calls it) opens the file it truncates and cuts it
  with `set_len` — same file, same identity — then re-walks and refreshes
  the cached state. The CLI `receipts repair` holds no append handle at
  all: it calls the static `repair` and opens fresh. `repair_tail` has no
  in-repo callers. Identity refusal cannot break repair, and the repair
  tests prove it still runs.
- **`truncate` / `create` return a fresh handle.** The old handle is
  stale by construction; the only in-repo `truncate` callers are two
  tests, and the round-4 test
  `a_replacement_at_the_same_size_and_start_is_not_trusted` already
  blesses refusal ("Either it refuses, or it re-reads and produces a log
  that walks"). The refusal takes the first branch, and the test still
  passes.
- **Two handles to the same file share its identity**, so interleaved
  appends through the lock keep working: the re-walk adopts the new state
  of the *same* file, which is not a replacement.
- **The kernel holds no `ReceiptLog` handle**; receipts live in memory
  and the CLI exports them with short-lived handles. No long-lived
  in-process writer exists to break.

Alternatives considered and rejected:

- **MAC verification during the walk/append (shape (a))**: stops forged
  substitutions but not a genuine-backup substitution — same key, genuine
  MACs — which is the finding's core case. It also requires plumbing the
  receipt key into a handle that today has no key, and would change the
  semantics of the public unverified `append` / `append_all` API, whose
  documented contract is that the chain is integrity, not authenticity
  (`append_verified` is the authenticated path). Rejected as insufficient
  for the finding and the larger API change.
- **Refusing only same-length replacements**: the identity check is
  length-independent, so the refusal covers every replacement — a
  different-length valid chain is refused by the same comparison. A
  length-scoped refusal would have left the general property open for no
  benefit.
- **Refusing when either identity is `None`**: a fresh `open` or
  `create` has no baseline — the first append's walk establishes one —
  and `repair_tail` refreshes the cached state with identity `None`.
  Refusing on `None` would break open-then-append and repair-then-append
  for no gain: with no baseline there is nothing to compare against, and
  adopting what is at the path is what opening a log means.

## Consequences

- On unix and Windows an open handle appends only to the file it walked:
  a swapped-in chain — forged or genuine — is refused before the walk,
  with the file untouched and the replacement chain still reading back
  intact. The two new regression tests in `tests/receipt_hardening_tests.rs`
  pin both forms (`an_open_handle_refuses_a_valid_replacement_chain`,
  XPL-RPC-07 probe arm C kept as a test, and
  `an_open_handle_refuses_a_genuine_backup_replacement`, which asserts
  the backup's MACs verify before and after the swap).
- A deployment that replaces a log file under a running writer must
  reopen the log: the refusal message says so. The first append after a
  fresh `open` still adopts whatever is at the path — the handle's
  baseline is established by its first append's walk, not by the open.
- No format change, no public API change. The unix behaviour for a
  broken-chain replacement is unchanged (the walk still refuses it); the
  only new refusal is for a *valid* chain in a *different* file.
- ADR-0021's residual line ("Off unix there is no stable file identity
  at the MSRV") is narrowed by this decision: it now holds only where
  neither platform's identity exists. On Windows the log file joins the
  lock (ADR-0030) in having a real file identity; the sentence's
  remaining scope is the fallback platforms.
- Residuals: a filesystem that reports a zero file index makes the log
  unusable rather than forgeable on the identity question (fail-closed in
  the same direction as the lock); NTFS record-number reuse is covered by
  the sequence number inside the 64-bit index. A hard link to the
  original log file shares its identity, but a hard link is the same
  file, not a replacement — appends through it are the same chain.
- The macOS leg needs no change: macOS is unix and keeps the `(dev, ino)`
  path. No macOS execution was needed for this fix, and none was run.
