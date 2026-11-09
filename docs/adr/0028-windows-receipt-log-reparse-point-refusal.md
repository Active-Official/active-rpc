# ADR 0028 — Refuse reparse points at the receipt-log open on Windows

**Status:** Accepted 2026-11-09 (XPL-RPC-01).

## Context

The receipt log's two guarded opens (`open_log_write`, `open_log_read`,
`src/receipts.rs`) refused a symlink atomically with the open on unix
(`O_NOFOLLOW`) but not on Windows. On Windows the open followed a symlink
to its target, and the post-open `is_file()` check passed, because the
target is a regular file. A receipt log redirected through a symlink or
other reparse point made the append path and the reader operate on
attacker-chosen bytes.

The pre-open checks (`refuse_symlink` / `refuse_writable_regular`) do work
on Windows — `std::fs::symlink_metadata` reports a file symlink there —
so a link planted *before* an append or a repair was already refused. The
hole was the open itself: a link swapped in between the check and the open
(the check-then-open race ADR-0021 records as accepted on unix only
because `O_NOFOLLOW` closes it there), and the read paths that have no
pre-open check at all (`nonce_of`, `read_sample`), which read through a
planted link unconditionally.

## Decision

On Windows, both guarded opens set `FILE_FLAG_OPEN_REPARSE_POINT`
(`0x0020_0000`) on the open, so the open returns a handle to the reparse
point itself instead of following it, and then refuse when the handle's own
metadata carries `FILE_ATTRIBUTE_REPARSE_POINT` (`0x0000_0400`). The
refusal is atomic with the open — there is no check-then-open window — and
it refuses any reparse point (symlink, junction, or other tag), not just
file symlinks. The existing `is_file()` check stays as a backstop.

The two flag values are spelled out as constants in `receipts.rs`. The
crate forbids `unsafe` code and has no `windows-sys` dependency; both
values are stable Win32 constants, and both operations used
(`OpenOptionsExt::custom_flags`, `MetadataExt::file_attributes`) are safe
`std` APIs, so no carve-out or dependency was needed.

## Consequences

- A reparse point at the log path is refused by every entry point that
  opens the log (append, repair, open, read, lock-nonce read, sample read),
  on both platforms, at the open itself. The pre-open checks remain as the
  first line and the clearer error in the common case.
- The refusal error is `rpc/receipt` with the message "the receipt log
  path is a reparse point".
- No behaviour change for a normal log file: the flag is a no-op for a
  non-reparse file, and the handle is used exactly as before.
- Residuals (separate findings, not closed here): the lock's liveness
  check still degrades to an age rule on Windows (XPL-RPC-02), lock
  identity is still a plaintext nonce off unix (XPL-RPC-03 / XPL-RPC-08),
  the fast path still trusts mtime on coarse filesystems (XPL-RPC-06),
  and the fast path still has no file identity on Windows (XPL-RPC-07).
