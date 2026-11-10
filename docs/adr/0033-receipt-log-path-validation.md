# ADR 0033 — Receipt-log paths are validated at creation, uniformly on all platforms

**Status:** Accepted 2026-11-09 (XPL-RPC-10, XPL-RPC-11).

## Context

A receipt log is named by a path the operator supplies, and until this
decision nothing validated that path. The round-1 audit (§XPL,
XPL-RPC-10, XPL-RPC-11) found four ways the name can be wrong, all in the
same code path — `ReceiptLog::create` / `create_locked`
(`src/receipts.rs`) — and recommended fixing them together as path
validation at `create`, uniform on all platforms:

1. **Case collision (XPL-RPC-10, High).** `log.arrl` and `LOG.arrl` are
   two files on Linux/ext4 and one file on NTFS and default
   case-insensitive APFS, and their `.lock` and staging files collide the
   same way. Creating the second log either refuses (lock held) or
   appends both streams into one file — two audit logs silently become
   one, with interleaved receipts and a corrupted chain.
2. **Reserved device names (XPL-RPC-11, Medium).** `CON.arrl`,
   `NUL.arrl`, `COM1.arrl`, `AUX.arrl` are accepted as plain files on
   Linux; on Windows these are devices. `create` on `CON.arrl` opens the
   console device or fails — the log is never created, or worse, writes
   go to a device.
3. **Long paths (XPL-RPC-11, Medium).** A 289-character total path is
   accepted on Linux; on default Windows (`LongPathsEnabled` off)
   MAX_PATH 260 rejects it. A log created on Linux cannot be opened on
   a default Windows host.
4. **Staging-suffix cap (XPL-RPC-11, Medium, all OSes).**
   `install_staged` writes `<log>.writing-<pid>-<nanos>` (~35
   characters), pushing a 235-character single component over the
   255-byte component limit, so `create` fails with "cannot create the
   receipt log" — the error does not say why.

W6 verified both findings PARTIALLY CONFIRMED on real Windows
(`results/W6-R1-XPL-BND/RESULTS-W6-R1-XPL-BND.md:89-99`,
`logs/w6-paths-audited.log`): the case collision is visible (the second
create is refused with "already holds records" — the collision showing
through the differently-cased name) but the two logs did not merge in
that run; all six reserved names were refused, but with misleading lock
errors ("the receipt log lock was displaced by another process" for
CON/NUL/COM1/AUX, "cannot lock the receipt log" for PRN/LPT1), not
validation; a 317-character path was accepted (`LongPathsEnabled`=1 on
that machine); a 235-character component was refused with "cannot create
the receipt log".

Re-confirmation at HEAD `2ded7d5`, before this fix, reproduced W6
exactly (probe log `scratch/F1-RPC/xpl10-w6paths-prefixed.log`) and added
two sharper facts the fail-before regression tests pin:

- A case variant of an **empty** existing file does not even refuse
  pre-fix: `create(LOG.arrl)` succeeds, because the zero-length branch
  of `install_staged` removes the "empty" file and installs the new log
  under the colliding name.
- `truncate` through a case variant **succeeds** pre-fix and renames a
  fresh header over the file the other name denotes — the dangerous
  direction: truncating `LOG.arrl` wipes `log.arrl`'s records on NTFS.

## Decision

Validate the log path in `create_locked`, before the lock is taken or
any file is created, with one function, `validate_log_path`
(`src/receipts.rs`), called by `create`, `create_starting_at` and
`truncate` alike. A refused path leaves no lock or staging file behind,
and the refusal names the rule it violates. The rules, and the numbers
behind them, are public constants (`MAX_LOG_PATH_CHARS`,
`MAX_LOG_NAME_BYTES`) so the CLI help and this record state the same
ceilings as the code enforces:

- **Case collision.** If a sibling in the parent directory differs from
  the requested file name only by case, refuse, naming both names. The
  comparison is Unicode lowercase over the directory listing, on every
  platform — so the behaviour is platform-uniform and the refusal also
  fires on Linux when a case variant exists, as the audit's regression
  probe requires. A byte-identical sibling is not a variant: that is the
  same file, and the existing-content check reports it. A parent that
  cannot be listed (it does not exist yet) has no sibling to collide
  with, so the check is skipped there.
- **Reserved device names.** Refuse when the final component's stem,
  case-insensitively, is one of `CON PRN AUX NUL COM1–COM9 LPT1–LPT9`,
  after stripping trailing dots and spaces from the component and the
  stem — so `NUL.`, `CON ` and `COM1.` are refused exactly like `NUL`
  and `CON`. The check is on the stem (the part before the first `.`),
  because Windows treats `CON.arrl` as the console device: the extension
  does not save it. `COM10` and `auxiliary` are not devices and pass.
  This check runs first because it needs no filesystem access, and a
  device name must never reach the lock.
- **Total path.** Refuse when the path is 260 characters or more,
  measured on the absolute path (a relative path is joined onto the
  working directory first, because that is the path the OS opens) in
  UTF-16 code units, the unit Windows counts. 259 is the longest path a
  default Windows host can open (MAX_PATH 260 includes the terminating
  NUL), so the ceiling is enforced at 260, not 259. The ceiling applies
  on every platform: a log created on Linux must open on Windows.
- **Final component.** Refuse when the final component, in bytes (the
  filesystem component limit is in bytes), plus the longest the staging
  suffix can be, exceeds 255 bytes. The suffix is
  `.writing-<pid>-<nanos>`: `.writing-` (9) + pid (a `u32`, at most 10
  digits) + `-` (1) + nanos (a `u64`, at most 20 digits) = 40 bytes at
  most, so the log name itself may be at most 215 bytes. The suffix
  format is unchanged; the validation guarantees the staging create can
  never fail for length, which is what the audit's "shorten the suffix"
  alternative was for.

When both the total and the component ceilings are exceeded, the total
is reported first: it is the more general rule (the path itself is
unportable whatever the component). W6's 235-character component under
an 80-character prefix is such a case — 296 characters total — and is
refused with the total-path error, which is true and actionable.

The staging step itself also names its cause now: if opening the staging
file fails and the staged path is 260 characters or more, the error says
the staging suffix pushed the path past the limit, instead of the
generic "cannot create the receipt log". A deep directory with short
components can pass the log-path ceiling and still exceed it once the
suffix is appended, and that failure used to be cryptic.

`open` and `repair` do **not** validate. They work on a log that already
exists, and refusing to open evidence created before this check — or on
another platform, where a case-variant pair can be two legitimate,
distinct files — would strand it. The collision can only be *created*
by `create` (and `truncate`, which funnels through the same
`create_locked`), so that is where it is refused. The CLI
`receipts dump` help states the four rules, so an operator meets them
before the refusal.

Alternatives considered and rejected:

- **Platform-gated checks (Windows-only).** Rejected: the finding is
  that a log created on one platform must open on the others, and a
  Windows-only refusal would still let Linux create the unportable log.
  Uniform refusal is the audit's recommended shape and the whole point
  of the fix.
- **Measuring the path as given (relative).** Rejected: the OS resolves
  a relative path against the working directory, so a short relative
  path can still be a 300-character path to the OS. The absolute path is
  what is measured. `.` and `..` are left in place — they only inflate
  the count, so the check stays fail-closed.
- **Shortening the staging suffix (drop nanos, use a counter).** Rejected
  for now: it changes the on-disk staging names (and the sweep logic
  that matches them) to raise the component ceiling from 215 to ~239
  bytes, a marginal gain, while the validation plus the named error
  already fixes the user-facing defect — a cryptic failure at the staging
  step becomes a legible refusal at `create`. Recorded here as the
  option to revisit if the ceiling ever needs raising.
- **Prefixing paths with `\\?\` on Windows instead of a ceiling.**
  Rejected: every file operation on the log, lock and staging paths
  would need the prefix, a larger change for the same portability, and
  the ceiling is the uniform, legible option the audit lists first.
- **Refusing at `open` as well as `create`.** Rejected for the reason
  above: on Linux a case-variant pair is two legitimate files, and a
  blanket refusal at `open` would break working deployments to fix a
  collision that `create` can no longer produce. A pre-existing ambiguous
  pair remains openable; on Windows it was already one file.

## Consequences

- A log path that cannot name a log portably is refused at `create` on
  every platform, with the rule named in the error: no more "already
  holds records" for a case collision, no more lock errors for a device
  name, no more silent acceptance of a 300-character path, no more
  "cannot create the receipt log" for a name the staging suffix cannot
  fit. The ten new regression tests in `src/receipts.rs`
  (`path_validation_tests`) pin all four rules, including the exact
  boundaries (259 accepted / 260 refused; 215-byte component accepted /
  216 refused) and the `truncate`-through-a-case-variant wipe.
- The only behaviour change for legitimate flows is fail-closed: a log
  name that used to create is now refused when it is a device name, a
  case variant of an existing file, 260+ characters in total, or over
  215 bytes as a component. Each refusal tells the operator what to do
  (choose another name / a shorter path). No format change, no public
  API change beyond the two new public ceiling constants.
- Residuals, recorded honestly:
  - A 255–259-character log path passes validation, but its `.lock`
    file (5 characters longer) can still exceed MAX_PATH on a default
    Windows host, and the failure then surfaces as the pre-existing
    lock error. The lock is acquired by `open`/`append` as well as
    `create`, so tightening the ceiling to 254 would have changed the
    audit's number to cover a shared lock-acquisition rough edge; the
    ceiling stays at the audit's 260 and the edge is recorded here.
  - A 220–259-character log path passes validation, but its staged path
    (+~40) can still exceed MAX_PATH on a default Windows host at
    `create`. That failure is now named by the staging error above,
    rather than the generic refusal.
  - The case comparison is Unicode lowercase, not NTFS's exact folding
    table; it covers the realistic collision (same letters, different
    case). A non-UTF-8 name is measured through its lossy form, so the
    length count is approximate there.
- The macOS leg needs no change and none was run (no macOS host): the
  validation has no `cfg` gates — it is a directory listing, a stem
  comparison and two length counts — so it compiles and behaves the
  same on macOS, where default APFS is case-insensitive and the same
  rules apply. The Linux Docker leg runs the same tests (the reserved
  and length rules are platform-independent; the case tests use real
  files and pass there too, because the refusal is uniform).
- ADR-0021 defines the durable log format and says nothing about path
  validity; this decision adds the path rules it did not state, and does
  not amend it.
