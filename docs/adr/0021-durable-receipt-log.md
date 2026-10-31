# ADR-0021 — Durable receipt log (`ARRL`)

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

An append-only file, `ARRL`:

```text
header: "ARRL" | version u8 | reserved 0,0,0
record: len u32 LE | sequence u64 | at_ms u64
      | cap_len u16 | cap (16 hex chars)
      | method_len u16 | method (UTF-8, 1..=1024 bytes)
      | mac [32]
      | previous [32]
      | record_hash [32]
```

- `record_hash = Blake3("active-rpc/receipt-log/v1" || body)`, where `body` is
  every field before it, including `previous`. The first record links to 32
  zero bytes.
- `len` covers the body plus `record_hash`; a record over 64 KiB is refused.
- `sequence` must be exactly `previous sequence + 1`, starting at 1. An export
  that begins mid-stream (a wrapped ring) is refused rather than accepted with
  a gap.
- Appending walks the chain once, validates it, and writes the batch with one
  `write_all` plus `sync_data`. A crash can leave a partial trailing record,
  which the reader refuses; it cannot leave a broken link in the middle.
- `verify_chain` needs no key: it checks magic, version, reserved bytes, record
  hashes, links and sequence continuity.
- `verify_macs(secret)` additionally checks each `mac`, which proves the kernel
  produced the receipt.
- `head_hash()` returns the chain head so an operator can pin it out of band;
  without pinning, deleting a whole suffix leaves a shorter but self-consistent
  log.
- The CLI drives it: `receipts dump`, `receipts verify`, `receipts show`.

## Consequences

- The log holds correlation ids, method names and times. It never holds
  arguments, values, capability ids or secrets; `receipts.rs` refuses to encode
  a record whose correlation id is not 16 hex characters or whose method is
  empty or over 1 KiB.
- Rotation is manual: start a new file and pin both heads. A built-in rotation
  with a manifest is additive work.
- Append cost is linear in the log length because the chain is revalidated on
  each append. A long-lived kernel should batch (`append_all`) rather than call
  `append` per receipt; a future revision can cache the head with an exclusive
  lock.
- The MAC is keyed by the kernel secret, so the same receipt cannot be
  transplanted between kernels or edited without detection (`receipts_tests`).
- A log is evidence, not a signature: it proves internal consistency and kernel
  origin, not who holds the file. Authenticity of the file itself is the
  deployment's concern (sign the export with the release key).
