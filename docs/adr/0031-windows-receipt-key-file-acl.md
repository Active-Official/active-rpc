# ADR 0031 — Receipt-key file ACL check on Windows

**Status:** Accepted 2026-11-09 (XPL-RPC-09).

## Context

The receipt key proves an audit log, and a leaked key lets a stranger
forge one — so `read_receipt_key` (`cli/active-rpc-cli/src/main.rs:1906`)
refuses a key file other accounts can read. The refusal was unix-only:
the `mode & 0o077 != 0` check sits inside `#[cfg(unix)]`, and the doc
comment said "Windows ACLs are the deployment's responsibility, so the
check is unix-only and documented." No Windows ACL check existed
anywhere, so on Windows a receipt key readable by other users was
silently accepted. The W6 verification probe reproduced it
(`WORLD-READABLE-KEY-EXIT-0`): a key with `BUILTIN\Usuarios RX` verified
— exit 0, `ok 3 receipts, start 1, head 88ba3612…, macs verified`.

A fresh file under `%TEMP%` carries an inherited ACL that lets other
accounts read it (`SYSTEM:(F)`, `BUILTIN\Administradores:(F)`, the
owner `(F)`, plus an inherited `BUILTIN\Users` read entry), so a key
created in the ordinary way was world-readable by default — the
finding's shape, not an exotic configuration.

One more fact shaped the fix: files created by an elevated session are
owned by `BUILTIN\Administradores`, not by the operator's account
(observed on this machine), and a non-elevated administrator needs an
explicit ACE for their own account to open the file at all, because the
`Administrators` SID is deny-only in a filtered token.

## Decision

Implement the fix the audit recommended — query the file's DACL on
Windows and refuse unless only the owner (and explicitly allow-listed
accounts) can read it — with the `unsafe` confined to a one-function
helper crate instead of a carve-out in the CLI (same shape as
`file-identity`, XPL-RPC-08):

- New crate `key-acl/` (package `active-rpc-key-acl`, v0.1.0,
  `publish = false`), whose whole public API is one safe function,
  `check_key_file_acl(file: &std::fs::File) -> Result<(), String>`,
  returning `Ok(())` when no ACE grants read to any SID but the owner,
  `SYSTEM` (`S-1-5-18`), `Administrators` (`S-1-5-32-544`), or a member
  of the local Administrators group — `Err(reason)` naming the offending
  SID otherwise. The CLI depends on it only under `cfg(windows)`; unix
  keeps the mode check, and any other platform keeps the stub
  (`Ok(())`), where the caller's unix check is the whole test.
- The allow-list is exact, and it is documented in the helper crate:
  "read" is `FILE_READ_DATA` or the generic forms that include it
  (`GENERIC_READ`, `GENERIC_ALL`); an ACE that grants only write,
  execute, attributes, or `READ_CONTROL` does not leak the key's bytes
  and passes. Inherited ACEs count exactly like explicit ones: the
  inherited `BUILTIN\Users:(RX)` on a file created under `%TEMP%` is the
  finding. A `NULL` DACL (no access control at all — FAT/exFAT, which
  have no ACLs) is refused: the invariant cannot be established there.
  Granting ACE types that cannot be parsed (compound, object,
  callback-object) fail closed, as does an unknown ACE type; deny, audit,
  and system ACE types grant nothing and are skipped, and a deny ACE does
  not rescue an allow ACE. An ACL that cannot be read at all is refused
  (fail closed: an unreadable ACL proves nothing).
- The members count because `Administrators` is allow-listed as a group,
  and a group allow-list means its members: an administrator can read any
  file when elevated (taking ownership and the backup privilege bypass
  the DACL), so the DACL cannot keep administrators out and refusing
  their ACE would be theater. The check's job is to keep the key from
  non-administrator accounts — which is also why a file created by an
  elevated process (owned by `Administrators`, with an ACE for the
  operator's own account) passes, instead of being refused for granting
  read to someone who is not the owner SID. The membership is resolved
  from the well-known SID through `LookupAccountSidW` (the group's name
  is localised — `Administradores` here — so it is never assumed) and
  `NetLocalGroupGetMembers` level 0; a lookup that fails for any reason
  counts as "not a member".
- The CLI wires it in as a `#[cfg(windows)]` arm in `read_receipt_key`
  that opens the file and checks the opened handle's ACL, so the check
  describes the file actually opened rather than a path re-read
  afterwards (same shape as the unix arm). The refusal is the same
  `CliError::usage` class as the unix refusal (exit 2):
  `"{path:?} is readable by other accounts ({reason}); restrict the
  file's ACL to the owner"`.

Alternatives considered and rejected:

- **A new registry dependency**: `windows-sys 0.61.2` is already in the
  lockfile as a transitive dependency; the helper adds no new registry
  crate to the graph (verified: the lockfile gains only the
  `active-rpc-key-acl` entry, plus the three helper packages from
  XPL-RPC-02/04/08 whose entries the lockfile was missing).
- **Stable `std` ACL APIs**: there are none — stable `std` exposes no
  ACL, and `MetadataExt` has no ACL surface. The probe lives behind
  `windows-sys`, as with `file-identity`.
- **Refusing unless the owner SID alone has read**: breaks the two real
  configurations on this machine — a file created elevated is owned by
  `Administrators` with an ACE for the operator, and a non-elevated
  administrator needs an explicit user ACE to open the file at all. Under
  strict SID equality neither configuration has a working setup. The
  membership rule is what makes the check usable, not a weakening of it:
  administrators were never excludable by a DACL in the first place.
- **Shelling out to `icacls` or PowerShell at runtime**: fragile (localised
  output, quoting, `PATH`) and slower, for what is one API call
  (`GetSecurityInfo`) plus an ACE walk. `icacls` stays where it belongs:
  the tests and the operator recipe.
- **Checking the path instead of the handle**: a TOCTOU gap — the check
  must describe the file actually opened (same argument as the unix arm
  and ADR-0030's identity check).

What was deliberately not done: the read-vs-open window (the file can be
re-ACL'd between the check and the read) is shared with the unix arm and
is not closed here — the check is a permission gate at open time, not a
continuous guarantee. The unix check is unchanged, and the receipt-log
paths are untouched: their Windows residual ("a replacement is detected
by content, not by identity") is still ADR-0021's.

## Consequences

- On Windows a key readable by any non-administrator account is refused
  with exit 2 before any MAC is checked, and the refusal names the
  offending SID (`S-1-5-32-545` for `BUILTIN\Users`). A default-ACL key
  under `%TEMP%` is refused until the operator restricts it:
  `icacls <path> /inheritance:r` then `icacls <path> /grant:r
  <owner>:(F)`, with the owner from `(Get-Acl <path>).Owner`.
- The unix behaviour is unchanged, and the CLI's refusal class is the
  same usage error on both platforms.
- Residuals (bounded, documented in the helper crate): the read-vs-open
  window above; a file on FAT/exFAT is refused outright (fail-closed);
  `docs/hardening/COPILOT-MARATHON.md:5630`'s "unix-only" note is now
  stale — a historical log, left as-is and superseded by this ADR.
- The macOS leg needs no change: macOS is unix and keeps the mode check.
  No macOS execution was needed for this fix, and none was run.
