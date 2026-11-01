# ADR-0016 - Capability receipts

**Status:** accepted (2026-10-31). Additive: no wire change.

## Context

An operator needs to answer "was this call authorized, and under which
capability, and when" after the fact. The event log already records refusals and
reclamations, but an accepted call's decision is only visible as the absence of
an error. Auditors also need the record to be tamper-evident, and it must not
become a second place where arguments or secrets leak.

## Decision

A kernel can enable receipts (`Agent::enable_receipts`). Every call that reaches
dispatch appends a `Receipt` to a bounded ring (`MAX_RECEIPTS = 1024`):

```text
sequence u64 | cap correlation id | method | at_ms u64 | decision | mac [32]
```

- The mac is `blake3::keyed_hash(kernel_secret, domain || fields)`. It proves
  the record came from this kernel and was not edited; it is not a public-key
  signature and is not intended to convince a third party that never shared the
  secret.
- The capability appears as its correlation id, never its authority id.
- Arguments, values, payloads and secrets never enter a receipt.
- Both outcomes are recorded. `Decision::Admitted` and
  `Decision::Refused(code)` carry the decision the kernel took at dispatch, so a
  call that was queued and then refused (revocation, expiry, identity, budget,
  scope, tool policy) is evidence of a refusal, not of an authorization.
- Receipts are opt-in and cleared when disabled, so kernels that do not need
  them pay nothing. `Agent::receipts_dropped` counts evictions and clears, so a
  short ring never reads as a short history.

## Amendments (R-13, hostile review round 1)

- **Seal at dispatch, not at queue.** The original decision recorded an admitted
  call when it was queued. A hostile review found the hole (F4): a call queued
  under a live capability and revoked before the kernel ran it kept an
  "authorized" receipt even though the kernel refused it. The seal now happens
  after the dispatch-time checks, with the decision as a record field.
- **Method names are checked at the grant.** `check_method_names` runs at mint,
  mint-from-record and attenuate: a granted method must be 1..=1024 bytes and
  free of control characters, because a receipt and its log cannot carry
  anything else (F8/F9).
- **Evictions are counted.** `receipts_dropped` is a monotonic counter plus one
  `receipts.dropped` event when the ring starts dropping, which keeps the event
  tape from being flooded one eviction at a time (F6).
- **Recovery from a wrapped ring.** Receipts keep their original sequence, so an
  exported window starts at the oldest retained sequence and
  `ReceiptLog::create_starting_at` records where it begins (see ADR-0021).

## Amendment (R-13 round 2)

- **A purpose-derived key seals receipts.** The mac used to be keyed by the
  kernel secret, which also mints capability ids, so proving a log handed the
  prover the authority to mint. Receipts are sealed with
  `derive_receipt_key(secret)` (`active-rpc/receipt-key/v1`), exposed as
  `Agent::receipt_key`; a verifier holds that key and nothing more.
- **A refusal before dispatch is still a decision.** A job failed by an
  unorderable pipeline, a vanished provider or a destroyed lane records
  `Refused(code)` through the same seal point, so an audit never shows a gap
  where a refusal happened.
- **Continuing a log across a restart.** `Agent::set_receipt_sequence` adopts the
  next sequence, and the kernel must read the wall clock (`use_wall_clock(true)`)
  so its times do not start again at zero.

## Consequences

- `Receipt` and `MAX_RECEIPTS` join the public surface; `Agent::receipts` and
  `Agent::verify_receipt` are the read paths.
- A future cross-party receipt needs an asymmetric signature and a published
  key; that is a new ADR and a wire change.
- The ring is per kernel and in memory. Durable receipts belong with the
  persistence work, not here.
