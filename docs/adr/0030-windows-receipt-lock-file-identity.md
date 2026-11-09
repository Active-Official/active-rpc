# ADR 0030 — Receipt-lock file identity on Windows

**Status:** Accepted 2026-11-09 (XPL-RPC-08).

## Context

The receipt log's writer lock (`LogLock`, `src/receipts.rs`) proves
ownership by the file the holder created: on unix `still_holds` compares
the held handle's `(dev, ino)` against the path, so a local user who reads
the plaintext nonce, unlinks the lock and recreates the same text does not
fool the holder — the recreated file has a different inode and the holder
refuses to write (R-13 round 11, L-3). On Windows every ownership check
was a nonce-text comparison instead (`still_holds`, the `Drop` claim
check, the acquire write-failure cleanup, and `take_stale`'s moved-file
verification), because stable `std` exposes no file identity there:
`MetadataExt::file_index` needs the unstable `windows_by_handle` feature.
The nonce is written in cleartext (`active-rpc-lock v1 <nonce> pid <pid>
started <ms>`), so any local user with directory read could copy it, and a
verbatim copy was byte-identical and indistinguishable. The W6
verification probe reproduced it on Windows (`PASS
xpl-rpc-08/copied-lock-indistinguishable`), and the lock-steal probe
showed the steal deleting a file it never judged — text-only identity
(XPL-RPC-03's Windows side, same root cause).

A displaced holder that still believed it held the lock could append a
second chain into the log, and a displaced holder's `Drop` could delete a
replacement lock it did not own. The lock is the mutual-exclusion
mechanism for the audit log, so the finding is High.

## Decision

Implement the fix the audit recommended — verify ownership by handle
identity, not by re-reading text — with the `unsafe` confined to a
one-function helper crate instead of a carve-out in this crate:

- New crate `file-identity/` (package `active-rpc-file-identity`, v0.1.0,
  `publish = false`), whose whole public API is one safe function,
  `file_identity(file: &std::fs::File) -> Option<(u64, u64)>`, returning
  `(volume serial, file index)` from `GetFileInformationByHandle`. The
  root crate depends on it only under `cfg(windows)`; unix keeps the
  `(dev, ino)` checks, and any other platform keeps the nonce-text check
  as the best available.
- `still_holds` on Windows compares the held handle's identity against
  the path's (opened and identified, so the identity describes the file
  actually opened; a symlink at the path is refused outright). Either side
  unavailable means the holder cannot prove ownership, so it fails closed
  — as on unix. The same identity comparison replaces the text check in
  the `Drop` claim verification, the acquire write-failure cleanup, and
  `take_stale`'s moved-file verification (via `lock_file_is_judged`,
  which also requires the modification time to match, as the unix branch
  does — the identity alone is reusable).
- `lock_state` now records the judged file's identity on Windows too
  (`FileIdentity { dev: volume serial, ino: file index, modified }`), so
  the steal proves it moved the file it judged.
- The nonce stays in the lock file: it is what an operator reads, and the
  steal's claim file is named after it. It is no longer a proof of
  ownership on unix or Windows — only the fallback platforms still check
  it, and the `LogLock.nonce` field documents that.
- A zero file index reports `None` (no identity) rather than an identity:
  filesystems that supply no file IDs (FAT/exFAT) report zero, and
  treating zero as an identity would equate every file on the volume.
  Failing closed there is consistent with the log itself: `create` already
  fails on those filesystems (the header install needs a hard link).

Alternatives considered and rejected:

- **Weakening the crate policy** (`#![forbid(unsafe_code)]` to `deny` plus
  a scoped `#[allow(unsafe_code)]` on one function): `forbid` cannot be
  overridden by `allow`, so the change would have weakened the crate-wide
  invariant — the same invariant the shm transport and ADR-0003 cite as a
  design choice. The helper crate preserves the invariant exactly:
  `active-rpc` still forbids `unsafe` everywhere. (Same argument as
  ADR-0029.)
- **Using `std::os::windows::fs::MetadataExt::file_index`**: it needs the
  unstable `windows_by_handle` feature and does not compile on the stable
  toolchain (proven by the XPL-RPC-07 probe, which tried it). There is no
  stable `std` API for the file ID.
- **Storing the nonce in a named kernel object** (the audit's alternative):
  it would bind ownership to a kernel object instead of the file, but it
  is a second mechanism beside the lock file — new lifetime, naming, and
  cleanup rules — where the file-index check reuses the exact shape unix
  already proves. Rejected as the larger change for the same guarantee.
- **Holding the lock file open with no share-delete** (the audit's other
  alternative): the holder already holds the handle open, but Rust's
  `std` opens share read/write/delete by default and offers no stable way
  to change the share mode, so the handle alone cannot block an
  unlink/recreate. The identity check is what makes the unlink visible.
  (A future `File::options` share-mode API could add the block as
  defence in depth; it is not needed for the guarantee.)
- **A new registry dependency** (e.g. a file-identity crate): not in the
  lockfile, so it would need a network fetch for one call.
  `windows-sys 0.61.2` is already in the lockfile as a transitive
  dependency; the helper adds no new registry crate to the graph
  (verified: the lockfile gains only the `active-rpc-file-identity`
  entry).
- **Wiring the same identity into the log's append fast path**
  (`identity_matches` / `same_identity`, which still return `true`
  unconditionally off unix): deliberately not done here. XPL-RPC-07
  closed that finding through RPC-05's keyed content sample, with the
  identity residual documented in ADR-0021; an identity mismatch there
  would only force the same re-walk the sample already forces. The lock
  is the finding in front of us, and the fast path is a separate, already
  closed decision.

## Consequences

- On Windows a byte-identical copy of a live lock is not the holder's
  lock: `still_holds` is false, the writer refuses, and the holder's
  `Drop` does not delete the replacement. A replacement carrying the
  judged nonce is not the judged file, so the steal preserves it. The
  unix behaviour is unchanged, and the nonce-text fallback remains only
  where neither platform's identity exists.
- The log's append fast path and reader are untouched: their Windows
  residual ("a replacement is detected by content, not by identity") is
  still ADR-0021's, and XPL-RPC-07's closure stands.
- Residuals (bounded, documented in the helper crate): a filesystem that
  reports a zero file index makes the lock unusable rather than forgeable
  (fail-closed); NTFS record-number reuse is covered by the sequence
  number inside the 64-bit index, and the steal additionally requires the
  mtime to match. A hard link to the original lock file shares its
  identity, but a hard link is the same file, not a second writer — no
  second `LogLock` can be acquired while the path exists — so it does not
  reopen the hole.
- The macOS leg needs no change: macOS is unix and keeps the `(dev, ino)`
  path. No macOS execution was needed for this fix, and none was run.
- ADR-0021's residual line ("Off unix there is no stable file identity at
  the MSRV") is narrowed by this decision: it now holds only for the log
  file's fast path and reader, not for the lock. The lock's half of that
  sentence is closed here.
