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
