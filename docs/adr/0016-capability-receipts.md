# ADR-0016 — Capability receipts

**Status:** accepted (2026-10-31). Additive: no wire change.

## Context

An operator needs to answer "was this call authorized, and under which
capability, and when" after the fact. The event log already records refusals and
reclamations, but an accepted call's decision is only visible as the absence of
an error. Auditors also need the record to be tamper-evident, and it must not
become a second place where arguments or secrets leak.

## Decision

A kernel can enable receipts (`Agent::enable_receipts`). Every admitted call
appends a `Receipt` to a bounded ring (`MAX_RECEIPTS = 1024`):

```text
sequence u64 | cap correlation id | method | at_ms u64 | mac [32]
```

- The mac is `blake3::keyed_hash(kernel_secret, domain || fields)`. It proves
  the record came from this kernel and was not edited; it is not a public-key
  signature and is not intended to convince a third party that never shared the
  secret.
- The capability appears as its correlation id, never its authority id.
- Arguments, values, payloads and secrets never enter a receipt.
- Only admitted calls are recorded. A refused call is visible in the event log
  with its `rpc/...` code.
- Receipts are opt-in and cleared when disabled, so kernels that do not need
  them pay nothing.

## Consequences

- `Receipt` and `MAX_RECEIPTS` join the public surface; `Agent::receipts` and
  `Agent::verify_receipt` are the read paths.
- A future cross-party receipt needs an asymmetric signature and a published
  key; that is a new ADR and a wire change.
- The ring is per kernel and in memory. Durable receipts belong with the
  persistence work, not here.
