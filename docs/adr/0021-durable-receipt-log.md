# ADR-0021 - Durable receipt log (`ARRL`)

**Status:** accepted (2026-10-31). New file format; the ARP1 wire is unchanged.

## Context

`Receipt` (ADR-0016) records that a capability authorized a call: a monotonic
sequence, the capability's correlation id, the method, the kernel time and a
keyed MAC. The kernel keeps the last `MAX_RECEIPTS` (1024) in memory, which is
enough for a live console and useless for an audit that needs to answer "what
did this agent do last Tuesday".

An exported log must satisfy three constraints that pull against each other:

1. it must be appendable while the kernel runs, without rewriting history;
2. a verifier without the kernel secret must still detect truncation,
   reordering and edits;
3. it must never carry arguments, values or secret material.

## Decision

An append-only file, `ARRL`, version 2:

```text
header: "ARRL" | version u8 = 2 | reserved 0,0,0 | start_sequence u64
record: len u32 LE | sequence u64 | at_ms u64
      | decision u8 | code_len u16 | code
      | cap_len u16 | cap (16 lowercase hex chars)
      | method_len u16 | method (UTF-8, 1..=1024 bytes)
      | mac [32]
      | previous [32]
      | record_hash [32]
```

- `record_hash = Blake3("active-rpc/receipt-log/v2" || body)`, where `body` is
  every field before it, including `previous`. The first record links to 32
  zero bytes.
- `len` covers the body plus `record_hash`; a record over 64 KiB is refused.
- `sequence` must be exactly `start_sequence + n` for the `n`th record. A gap is
  refused; a ring that wrapped exports with `create_starting_at(path, oldest
  retained sequence)`, so the window is honest about where it begins.
- Appending walks the chain once, validates it, and writes the batch with one
  `write_all` plus `sync_data`. A crash can leave a partial trailing record,
  which the reader refuses; it cannot leave a broken link in the middle.
- `verify_chain` needs no key: it checks magic, version, reserved bytes, record
  hashes, links and sequence continuity.
- `verify_macs(&derive_receipt_key(secret))` additionally checks each `mac`,
  which proves the kernel produced the receipt. The verifier takes the *derived*
  receipt key, never the master secret: the secret also mints capability ids, and
  handing it to a log checker would hand it authority. The key is symmetric, so a
  verifier holding it can also forge; receipts are evidence against a file or a
  process, not against in-process code.
- `head_hash()` returns the chain head so an operator can pin it out of band;
  without pinning, deleting a whole suffix leaves a shorter but self-consistent
  log, which `verify_against(expected_head)` detects.
- The CLI drives it: `receipts dump`, `receipts verify (--receipt-key-file |
  --expect-head | --chain-only)`, `receipts show`, `receipts repair`.

## Amendments (R-13, hostile review round 1)

A reviewer drove the v1 design with probes and found four high-severity holes
that the original decision did not cover. All four are closed; the format
changed to v2, and no deployment had produced a v1 file, so the reader refuses
v1 outright rather than carrying a second parser.

| # | Finding | Change |
|---|---|---|
| F1 | `append_all` never checked sequence continuity, so a wrapped ring (after 1025 calls) wrote a log its own reader refused and left the file unusable | The writer computes the expected sequence from the header's `start` plus the record count; `create_starting_at` lets a wrapped ring export its retained window (test: `a_kernel_ring_that_wrapped_exports_cleanly`) |
| F2 | A truncated prefix verified: dropping the last records leaves a shorter, self-consistent log | `verify_against(expected)` pins the head a verifier learned out of band; the CLI exposes it as `--expect-head` |
| F3 | Append was unauthenticated and the CLI never checked MACs, so a writer without the key could extend a log | `append_verified(key, ..)` refuses a receipt this kernel did not seal; `receipts verify --receipt-key-file` checks MACs and says `chain-only (unauthenticated)` when it does not |
| F4 | The receipt was sealed at queue time, so a call that dispatch refused (revoked, expired, identity mismatch) kept an "authorized" receipt | The seal happens at dispatch with the decision the kernel took; `Decision::{Admitted, Refused(code)}` is a record field, and the CLI prints it |
| F5 | Concurrent appends could interleave and corrupt the chain | `LogLock` takes a `create_new` lock file with a bounded retry; a second writer refuses instead of writing |
| F6 | Eviction and disable left no marker, so a short ring looked like a short history | `Agent::receipts_dropped()` counts evictions and clears; one `receipts.dropped` event marks the transition |
| F7 | The log was unbounded, reads pulled the whole file, and each append re-walked it (quadratic) | `MAX_LOG_BYTES` (64 MiB), `MAX_LOG_RECORDS` (100 000), reads through `take(ceiling + 1)`, and a cached `LogState` short-circuited by one `stat` |
| F8 | The kernel could seal a receipt its own log rejects (method empty, over 1 KiB, or with a control character) | `check_method_names` at mint, mint-from-record and attenuate; `append` applies the reader's predicates before writing |
| F9 | A method or code could inject a line into a log reader or a terminal | `valid_method` and `valid_code` on both encode and decode; the CLI quotes the method |
| F10 | Errors named a 0-based index | Errors name the receipt `sequence` |
| F11 | A bad header exited with the usage class | A damaged log is a refusal (exit 1); a missing path is usage (exit 2) |
| F12 | `create` truncated an existing log, destroying evidence | `create` refuses a non-empty log; `truncate` is the explicit "start over" |
| F13 | Records could be non-canonical (uppercase hex, arbitrary codes, reversed times) | One predicate per field shared by writer and reader; `at_ms` must not decrease; an unknown version is refused |

Two consequences follow from the review and are worth stating:

- **Chain is not authenticity.** A chain-only verify proves the file was not
  edited or reordered; it does not prove the kernel wrote it. Only
  `verify_macs` does with the derived key, and only a party holding that key can be
sure.
- **A prefix is a valid log.** Truncation is invisible to the chain by
  construction. Pinning the head is the operation that detects it, so an export
  should always publish its head next to the file.

## Amendments (R-13, hostile review round 2)

A second review verified all thirteen round-1 findings against the code and
found sixteen more. Ten were fixed here; the rest were absorbed into the design
below.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| B1 | high | `--secret-hex` put the *master* kernel secret (which mints capability ids) on the process command line, and the CLI and library both sealed with it | Receipts are sealed with a purpose-derived key: `derive_receipt_key(secret) = blake3::derive_key("active-rpc/receipt-key/v1", secret)`, exposed as `Agent::receipt_key`. The CLI takes `--receipt-key-file PATH` (unix: mode must be 0600) and never accepts the secret |
| B2 | high | a job failed before dispatch (unorderable pipeline, vanished provider, destroyed lane) settled with no receipt, so "no call" and "refused and undocumented" looked alike | `Job` carries `receipted`; `Kernel::seal_receipt` is the single seal point, called from dispatch and from `fail_job` when the job has none yet |
| B3 | high | the writer still accepted two records the reader rejects: `Decision::Refused("")` and a start near `u64::MAX` (which `saturating_add` let through while the reader used `checked_add`) | `encode_record` now calls `fields_are_representable` (the reader's own predicate), `append_inner` uses `checked_add`, and `create_starting_at` refuses a start within `MAX_LOG_RECORDS` of the ceiling |
| B4 | medium | a 64-*byte* non-ASCII key made the CLI slice inside a character and panic (exit 101) | `parse_hex32` checks the alphabet before slicing |
| B5 | medium | `receipts verify` read and walked the whole log six times, and could print a head no MAC check covered | `ReceiptLog::snapshot` reads once; the CLI verifies and prints from that |
| B6 | medium | a crash mid-`write_all` left the log unreadable *and* unappendable, with `truncate` (total loss) as the only exit | `ReceiptLog::repair` cuts back to the last complete record, and only when the tail is a genuinely torn record (its declared length runs past the end); damage inside the log is refused. CLI: `receipts repair` |
| B7 | medium | a stale `.lock` after a crash blocked appends forever and cost 1.18 s per attempt | The lock records pid and start time, and a lock older than `LOCK_STALE_MS` (120 s) is stolen |
| B8 | medium | `create`/`truncate` bypassed the writer lock, so a create racing an append left the fresh log corrupt | `create_locked` takes the same lock before `File::create` |
| B9 | medium | the default `receipts verify` exited 0 with `ok` for a forged *and* truncated log | One of `--receipt-key-file`, `--expect-head` or `--chain-only` is required; the unauthenticated mode is opt-in |
| B11 | low | `create` overwrote any existing file of ≤ 16 bytes | Any existing content is refused |
| B12 | low | the append encoded a whole batch before applying the size ceilings | Both ceilings are checked as they are crossed |
| B13 | low | a broken link named a 1-based index, not the sequence | Errors name `sequence` |
| B14 | low | a second session could not append to an existing log (the sequence restarted at 1; a virtual clock restarted at 0) | `Agent::set_receipt_sequence(next)`; documented with the wall-clock requirement, and tested |
| B15 | low | human-readable lines printed caller-supplied paths unquoted | Paths are printed with `{:?}` |
| B16 | low | `Event` grew a variant without `#[non_exhaustive]`, which is a breaking change for a downstream `match` | `Event` is `#[non_exhaustive]`, and the crate moves to 2.3.0 (ADR-0006: additive API is a minor bump) |

After round 2: the writer cannot produce a record its reader rejects, a refusal
always leaves a receipt, the key that proves a log is not the key that mints
authority, and a crash costs at most one record.

## Consequences

- The log holds correlation ids, method names, times and the decision. It never
  holds arguments, values, capability ids or secrets; `receipts.rs` refuses to
  encode a record whose correlation id is not 16 lowercase hex characters, whose
  method is empty or over 1 KiB or carries a control character, or whose refusal
  code is outside `[a-z0-9/-_.]` and 64 bytes.
- Rotation is manual: start a new file and pin both heads. A built-in rotation
  with a manifest is additive work.
- Append cost is linear in the batch: the cached state is revalidated only when
  the file changed under the writer (one `stat` in the common case), and the
  batch is written with one `write_all` plus `sync_data`. 2 000 appends run in
  well under a second on a developer machine and the test
  `many_appends_stay_linear` bounds it.
- The MAC is keyed by the derived receipt key
  (`derive_receipt_key(secret)`), never the master secret, which mints
  capability ids, so the same receipt cannot be
  transplanted between kernels or edited without detection (`receipts_tests`).
- A log is evidence, not a signature: it proves internal consistency and kernel
  origin, not who holds the file. Authenticity of the file itself is the
  deployment's concern (sign the export with the release key).

## Amendments (R-13, hostile rounds 3-7)

| # | Sev | Finding | Decision |
|---|-----|---------|----------|
| C1 | high | the stale-lock steal judged one file and renamed another, so two stealers could delete each other's live lock | The judgement reads the age and the nonce through **one** handle, and the steal claims a `create_new` file named after the judged nonce (sanitised, so a planted nonce cannot steer it). The live lock is never moved; the winner removes it only when its nonce is unchanged |
| C2 | medium | a lock old by time was stolen from a *live* writer, and the resulting chain could not be repaired | The writer keeps its own lock fresh while it writes (`LogLock::touch`, between `WRITE_CHUNK_BYTES` chunks), so "older than the ceiling" means "no live writer is making progress" on every platform. On Linux a lock naming a live pid is additionally honoured, but only for `LOCK_LIVE_GRACE_MS` (10 x the ceiling): an unbounded rule lets a planted lock naming a live pid stop the log for ever |
| C3 | medium | a read that landed mid-append could return a boundary-aligned prefix of the batch, publishing a head the file had already moved past | A reader that exhausts its bounded wait (11 x 20 ms) while a writer still holds a fresh lock refuses with "being written" instead of returning; a caller retries |
| C4 | medium | a provider that cancelled its own running call was receipted `Refused(promise-cancelled)` although the effect may have landed | A cancelled call that reached the provider is receipted `Admitted`, the same rule the withheld-reply contract applies to a lost answer |
| C5 | low | a stealer killed between claiming and removing left a claim that made one stale lock unstealable for ever | A claim older than the steal ceiling is removed and the steal retried |
| C6 | low | `LogLock::drop` read the lock with `read_to_string`, so a symlink to `/dev/zero` planted after the lock was created allocated without limit | The drop reads through the bounded lock parser |
| C7 | low | an adopted sequence gap left the pre-gap receipts in the ring, so the window could never be exported | A non-zero gap clears the ring and counts the hole and the cleared records |
| C8 | medium | the steal decided by age alone once the grace passed, so an attacker who replaced the lock path could make the writer's `touch` fail and then steal a live lock | Ownership is checked before every write: the writer keeps the handle `create_new` returned and refuses when the path no longer carries its nonce (`LogLock::still_holds`). A displaced writer therefore stops instead of racing, which is the invariant that matters |
| C9 | medium | the reader and the stealer used different windows (10 s vs 120 s), so a 30-second-old lock was final for a reader and live for a stealer: a slow append read as a damaged log | One predicate, `lock_is_live`, for both roles: a lock is live while it is younger than `LOCK_STALE_MS`, or older but naming a live pid within `LOCK_LIVE_GRACE_MS`. A reader that exhausts its wait refuses with "being written" |
| C10 | low | `touch` followed the lock path, so a planted symlink made the writer refresh another file | `touch` acts on the handle the writer created |
| C11 | low | the steal's check-then-remove was not atomic, and an expired claim let two live stealers through | The steal quarantines the lock by `rename` (atomic; one winner) and deletes the quarantined file; a displaced writer fails `still_holds` |
| C12 | low | a lock with a non-UTF-8 byte in its first bytes was unidentifiable, so it could never be stolen | The lock is parsed as lossy text |
| C13 | high | the quarantine moved whatever was at the lock path, and `create`/`truncate`/`repair` wrote without re-checking ownership | `take_stale` re-reads the moved file's nonce and preserves anything it did not judge (put back when the path is free, else kept as an orphan); every writer path calls `still_holds()` right after acquiring |
| C14 | medium | a future-dated lock was immortal, an empty lock unstealable, and a FIFO at the lock or log path blocked `open` for ever | A future timestamp reads as past the ceiling; an empty or unrenderable-nonce lock is quarantined like any other; both paths are type-checked with `symlink_metadata` before an open. The check is not atomic with the open: a local user with write access to the directory can still swap the path between them, which is a denial of service (the accepted class), and closing it needs an `O_NOFOLLOW`/`fstat` open on unix, recorded as a residual |
| C15 | medium | a pre-planted quarantine name blocked the rename | A failed first rename retries with a unique suffix the file's author cannot choose |
| C16 | medium | an in-flight read-only cancel was receipted as a refusal | A call that reached the provider is `Admitted`, read-only or not: the receipt records the dispatch decision, and the withheld answer is visible in the promise state |

The reader's refusal code is `rpc/receipt` with a message naming the writer; it is
a retryable condition, not damage. **A reader does not take the writer's lock**:
`ReceiptLog::open`/`snapshot` read and walk without it, so `receipts verify` exits
non-zero with "being written" while an append is in progress and an operator
retries. The lock is the writer's alone.

## Rounds 8-12 (hostile review, R-13)

Each row is a finding the audit loop closed after the C-table; the code comment
names the round where the rule lives.

| # | Sev | Finding | Disposition |
|---|-----|---------|-------------|
| R8 | high | the steal could move a lock it had not judged, and a displaced writer still appended | ownership is re-checked before every mutation; a steal renames, verifies the moved nonce and preserves what it did not judge |
| R9 | medium | a future-dated lock was immortal; an empty lock was unstealable; a FIFO blocked an open | a future timestamp reads past the grace; an empty or unrenderable nonce is quarantined; both paths are type-checked before an open |
| R10 | high | the writer held no ownership check between acquiring and writing | `write_all`, `create_locked` and `repair` re-check `still_holds` immediately before their mutation |
| R11 | high | a suspended creator could install its header over the new owner's log | `install_staged` re-checks, and the install is an exclusive hard link: a log created meanwhile is refused, never replaced |
| R11 | medium | an in-flight out-of-band resolve marked the job receipted without sealing | the pre-mark applies only while the job is queued; dispatch seals through the flag |
| R11 | low | text ownership could be copied by a local user; `Drop` checked then unlinked; a FIFO blocked the write opens; the parent directory was not flushed | ownership is the held handle's `(dev, ino)` on unix; `Drop` renames to a claim before verifying; `open_log_write` uses `O_NOFOLLOW` and the handle's type; the parent is flushed on unix |
| R12 | high | the header install was a *replacing* rename | the exclusive hard link above |
| R12/R13 | medium | ownership was checked once per batch, not per 1 MiB chunk | re-checked before each chunk and before the final flush (`write_all`) |
| R12/R13 | medium | the log path was checked, then re-opened; `repair` truncated through the new object | one verified handle per operation: `O_NOFOLLOW` on unix, `fstat` regular-file, then read/write/`set_len` on that handle; `repair` reads and truncates the same file |
| R12/R13 | medium | a reader could accept bytes read before its liveness probe, or a same-length replacement | the probe runs before and after the read, the length must equal the bytes walked, and on unix the path's `(dev, ino)` must still be the handle that was read |
| R13 | medium | `truncate` removed the old log before installing, and a filesystem without hard links could never install | `replacing` is one atomic rename under the lock; a zero-length file is removed before the exclusive link, and an unsupported link names that cause |
| R13 | medium | the sweep looked for `<log>.lock`-prefixed staging files, which production never creates | the sweep strips `.lock` and matches the log stem |
| R13 | medium | a cancel that ran while receipts were off marked the job receipted without sealing, so dispatch skipped it later | the flag is set only when a receipt was actually sealed, on every path (resolve, cancel, fail, dispatch) |
| R13 | low | the sweep read a future mtime as fresh | it reads as aged, like `lock_state`; an undeletable entry does not spend the budget |
| R12 | low | a planted fresh lock suppressed verification with an unhelpful message; leftovers were never swept; the unauthenticated writer was the ordinary one | the refusal names the lock's age, owner and pid (escaped); `acquire` sweeps aged claim/stale/orphan/staging files; the unauthenticated writers are documented and `append_verified` is the deployment path |
| R13r16 | medium | a partial magic-prefixed lock (a crashed write) was unjudgeable and wedged the log; `repair` refused a zeroed or flooded tail length | the magic is proof of origin, so a partial magic line is judged and stolen; an out-of-range tail length is cut only when no record survives there |
| R13r16 | low | the steal decided identity from text; the sweep deleted a sibling receipt log by name; the prefix walk materialised every record | unix compares the judged inode after the move; the sweep reads the log magic first and spares a receipt log; the walk returns only the offset and stops at `MAX_LOG_RECORDS` |
| R13r16 | low | a receipts-off interval was invisible, and a provider code could occupy the kernel's `rpc/` namespace | `receipts.disabled`/`receipts.enabled` events on every transition (a repeated call is not one); a provider code in `rpc/` or an unrepresentable one records as `rpc/provider` |

Accepted residuals: the check-then-open race on the lock path (a local user with
directory write can deny the log; an `O_NOFOLLOW` on the log path narrows the
same class for the lock and for the log itself), orphan files left by a killed
process until their age passes the ceiling, and the chain not being authenticity
(the receipt MAC is). **Off unix** there is no stable file identity at the MSRV,
so `(dev, ino)` comparisons are skipped there: the reader and the append fast
path keep the length, header and trailing-head checks, and a local writer who
can replace the file with a same-length copy is not detected. A deployment that
needs assurance on a non-unix host should read through a pinned head
(`--expect-head`) and the MAC, which do not depend on identity
(R-13 round 14, F2). `O_NOFOLLOW` is a unix flag: off unix the guarded opens
check the type of the object they actually opened, so a reparse point swapped in
between the type check and the open is followed. For the lock the window is a
bounded metadata read (`nonce_of` now uses the guarded reader, and the steal
unlinks the link, never a target), and a log open still refuses a device or FIFO
after the open. A host that cannot accept the window should keep the receipt
directory writable only by the service (R-13 round 16, F9/F4).

The append fast path no longer trusts mtime (RPC-05, fixed 2026-11-09). An
in-place same-length interior edit whose mtime was set back passed the length,
header, tail-head, identity and mtime checks, so the next append linked onto a
forged chain. The fast path now also verifies a keyed content sample on every
platform — eight 64-byte windows spread over the log body, placed by a
per-instance seed drawn from the operating system CSPRNG — and re-walks the
whole chain at least every 33 appends; a sample mismatch falls through to the
re-walk, which fails on the broken chain link and refuses the append. A log
whose record region is at most 512 bytes is verified byte-for-byte on the fast
path. The remaining residual is bounded, not open: a writer who evades the
sample in a large log can link at most 32 appends onto tampered history before
the scheduled re-walk refuses, and the tamper is then visible to every reader
(the walk fails at the edited record). A keyed MAC over (length, head, mtime)
was considered and rejected: the attack leaves all three inputs exactly as
cached, so such a MAC still verifies.

The lock no longer shares the no-identity residual above (XPL-RPC-08,
fixed 2026-11-09; ADR-0030). On Windows the lock's ownership is the file
identity — volume serial plus file index from `GetFileInformationByHandle`
through the `active-rpc-file-identity` helper crate — so a byte-identical
copy of a live lock is not the holder's lock, and the steal proves it moved
the file it judged. The residual as written still holds for the log file
itself: the reader and the append fast path keep the length, header and
trailing-head checks off unix, and a local writer who can replace the log
file with a same-length copy is detected by content (RPC-05), not by
identity. A deployment that needs assurance on a non-unix host should still
read through a pinned head (`--expect-head`) and the MAC.

`receipts verify` and the `--receipt-key-file` / `--expect-head` flags live in
the CLI crate that consumes this library; this ADR describes the library
contract, not a command-line surface (R-13 round 12, F9).
