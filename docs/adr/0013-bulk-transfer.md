# ADR-0013 - Bulk (carousel) transfer with per-chunk hashes

**Status:** accepted (2026-10-30).
**Date:** 2026-10-30
**Context:** Maturity Program C-6.3 (PROPOSAL §5.7)

## Problem

An ARP1 envelope body is bounded by the transport frame ceiling (64 MiB), and
Active Infinity images routinely exceed it. Raising the ceiling does not solve
the underlying problem: a multi-gigabyte single frame is unverifiable until the
last byte arrives, cannot be resumed after a disconnect, and forces both ends to
hold the whole body in memory at once. A flaky link turns one lost segment into
a restart.

## Decision

A body is transferred as a **plan** plus **self-verifying chunk frames**, both
carried as the **payload of an ordinary ARP1 call** (`plan`, `put`, `missing`,
`finish`) to a [`BulkProvider`](../src/bulk.rs). Carrying them as envelope
payloads is what binds a transfer to authority and to the byte budget: the
kernel charges an envelope payload against the caller's grant on ingress, and
the capability grants the methods, so a chunk costs the caller its grant and a
peer without `put` cannot push one. The codec itself is transport-independent.

**Plan** (`ARBL`, version 1): chunk size, total length, chunk count, per-chunk
Blake3 hashes and a root hash over the plan, the chunk hashes and a **transfer
context** (normally the request id and capability id of the envelope that opened
the transfer). The root is
`H(domain, version, chunk_size, total, count, chunk_hash[0..n], context)`, domain
separated from the Infinity content hash and from the chunk hash. The context is
never transmitted: both sides derive it, so a plan cannot float free of the
exchange that authorized it.

**Control frames.** `ARBM` names the missing indexes a receiver wants; `ARBF`
names the root and total the sender believes it completed, so a receiver refuses
a body from another transfer before assembling it.

**Chunk** (`ARBC`, version 1): index, offset, length, hash, bytes. A chunk is
refused unless the offset matches the index, the length matches the plan, the
hash matches the bytes *and* the plan's announced hash.

**Receiver rules.**

- A duplicate chunk with identical bytes is accepted (retransmission is
  idempotent); a duplicate with different bytes is refused.
- `missing()` drives the resume request. A receiver reconstructed from the plan
  asks only for the gaps: a reconnect never restarts the body.
- Each accepted frame is **charged before it is decoded** (`with_budget`,
  `accept_charged`), because the decode and the hash are the work the charge
  pays for; a refused charge leaves no state.
- `finish()` requires every chunk, checks the total length and re-verifies the
  body against the plan. A truncated or corrupted body never becomes a valid
  image.
- `BulkProvider` holds state **per object** (what `Provider::invoke` carries);
  attenuation preserves the object, so an object is expected to have one
  principal and a delegated capability shares its slot. `Provider::on_drop`
  releases both the in-progress transfer and an untaken completed body; an
  incomplete transfer expires after 60 s of inactivity and an untaken body after
  10 minutes, both against the kernel clock except a completed body, whose
  window starts at the end of the finish work (the stamp plus the real assembly
  duration, R-10 round 17), and the digest reply outlives the
  bytes. `plan` refuses to start a new transfer for an object whose completed
  body has not been taken, and `finish` is idempotent per object until a new
  plan is accepted for it, so a lost answer can be retried even after
  `take_body`. `missing` answers the indexes its request frame names (page-capped
  at 1 024, with `more` and `remaining`), keeps the transfer alive and never
  expires it by idleness. The finish reply carries `canonical`, `body_hash` (raw
  digest, never a content address) and `content`: the canonical hash of the
  **redacted** image when the body is an Infinity image. The transfer context is
  supplied by `BulkProvider::with_context`, one per provider instance.
- The **root is integrity, not authenticity**: `with_expected_root` pins the
  root the caller learned from the envelope, and a substituted plan is refused.
- A configurable ceiling bounds the bytes a receiver will assemble; the default
  is 1 GiB. `decode` checks the declared total and the chunk count (32 700, the
  largest plan **envelope** that fits `WireLimits::strict()`'s 1 MiB frame with a
  `max_path` descriptor and a cap delta) before the hash vector is allocated, and
  the plan constructor checks the count before it hashes anything.
- Every refusal inside `finish` leaves the chunks in place, so an error path
  cannot destroy bytes the caller paid for.

**Sender rules.** `frame_at(index)` is the streaming path; `frames_from(index)`
and `frames_for(missing)` are the batch paths. The missing list is deduplicated
and bounded by the plan, and a body is hashed once per chunk: a chunk frame
carries the hash it was built with, so a retransmission does not re-hash it.

## Consequences

- Memory is `O(body)` at the sender (it already has the bytes) and
  `O(received)` at the receiver, bounded by the ceiling. `finish` assembles
  before it releases the stored chunks, so its peak is the body plus the stored
  chunks: non-destructiveness on every refusal costs that one copy.
- The kernel meters ingress and egress against one grant, so a whole transfer
  needs `BulkPlan::required_grant()`: the plan frame, the chunk frames, the
  finish marker and a per-call reply allowance. `total + 53 x chunk_count` is the
  chunk frames alone. `BulkPlan::required_calls()` is the matching call bound,
  including one `missing` page per 1 024 chunks for a gaps-only resume; a caller
  that re-sends every frame uses `required_grant_with_resume()` and
  `required_calls_with_resume()`, about two passes. The wall grant is sized by
  `required_wall_ms()` (three linear passes at a rate measured well above the
  formula's assumption) **on both the capability and the lane**, because the
  kernel meters a call against the narrower of the two and a default lane's 5 s
  silently truncates it (`required_lane_wall_ms()` is the same number). The
  lane's cumulative `max_bytes` must cover `required_lane_bytes()`. A provider
  may bound the bytes it holds across objects with `with_max_live_bytes`, where
  each open transfer reserves twice the bytes it has **stored** plus **twice**
  the retained 32-byte-per-chunk hash vector and the 53-byte header once (the
  transfer's plan and the receiver's copy hold the per-chunk hashes; the header
  is shared):
  an unpaid plan holds only its vector, a `put` whose validated chunk would pass
  the bound is refused before it stores (an identical retransmission is free),
  and `BulkPlan::required_live_bytes()` is the bound a complete body needs
  (R-10 rounds 18 and 15). It covers the assembly, not an image
  **classification**: the redaction path holds two more body-sized projections,
  and the provider answers `content_error: memory` instead of classifying when
  its bound cannot cover up to `CLASSIFY_BODY_COPIES` (24) body lengths at the
  classification peak (7x measured with no secret nodes, 17-18x dense; use
  `BulkPlan::required_classification_bytes()` for the bound). Both plan copies
  retain the
  transfer context (charged twice); the receiver's missing-index set and the
  per-chunk map nodes are not charged, so the figure is a committed-state
  estimate (R-10 round 16, M4/L6).
- Every `finish` that runs out of wall is counted, whatever its grant: an
  attempt that presents `assembly_wall_ms()` and still expires is evidence that
  the estimate is wrong for this host, not a payment to forget (R-10 round 16).
  Three **sub-estimate** failures freeze the transfer for sub-estimate grants;
  a grant at the body's estimate is *funded*: it clears the count and runs, up
  to two funded assemblies (`FUNDED_ASSEMBLY_LIMIT`). Once that allowance is
  spent the freeze is monotone — no grant runs, including a smaller one, and one
  transfer runs at most `WALL_REFUSAL_LIMIT + FUNDED_ASSEMBLY_LIMIT` assemblies
  — so a funded reset cannot renew the cheap attempts (R-10 round 16, M1). A
  same-root `plan`
  frame does not clear the freeze. Both rules
  are why the sizing to mint is `required_wall_ms()`: the body's own cost with a
  per-chunk term and slack, never below the default grant. The stored chunks are
  never destroyed by a refusal: the non-destructiveness rule outranks the
  throttle, and `abort` is the caller's own way to discard what it no longer
  wants.
- A frozen transfer has exactly one way out: `abort` (or expiry). Closing it is
  what makes the freeze safe to hold: without it the only release is the idle or
  absolute window, and the object's slot and its reserved bytes stay held until
  then. `abort` acts on the object, so a host that mints a second capability on a
  shared object hands that party the right to discard it; the object model's
  one-principal rule is the boundary, and a provider cannot see the capability id
  today (recorded as RPC-11).
- A reply degraded because the grant was spent (`content_error: wall`) is
  recomputed once on a later `finish` that still has wall left, and the record
  then says it did, so a replay loop cannot buy repeated redactions (round 16).
- The finish reply carries `canonical`, and `content_error` when an image's
  address could not be computed (`wall`, `parser` or `memory` when the provider
  bound cannot cover the classification); a degraded reply is
  recorded as degraded instead of looking like a body without an address.
- `finish` is the one bulk path that reads the wall clock: the grant is a
  *duration* (`max_wall_ms`), which `Call::now_ms` cannot express, so the
  deadline is anchored at `Instant::now()` and checked between chunks, inside
  the verification pass (chunk by chunk, via `BulkPlan::verify_within`) and
  before the redaction. Every other lifetime is measured from the kernel clock;
  the completed window is the exception above because the work that produces it
  is real-time (R-10 round 17).
  The redaction pass itself is not interruptible, which is why the grant is
  sized for it and the reply degrades to `content_error: "wall"` when the grant
  is spent before it starts.
- The per-chunk hash means a receiver verifies each chunk on arrival; the root
  proves the whole set. It is a two-level Merkle shape without the tree.
- Authority stays on the ARP1 envelope: the provider is reached through a
  capability that grants `plan`/`put`/`missing`/`finish`/`abort`, and the ingress
  charge covers the chunk bytes, so the module cannot become an ambient file
  channel.
- A chunk frame is at most 8 MiB, while `WireLimits::strict()` caps an envelope
  body at 1 MiB: under that profile the sender must plan with chunks under the
  ceiling, or the frame is refused as `rpc/wire` before the provider sees it.
- The Infinity store and the CLI can use the same plan to move an image between
  hosts without a new protocol.

## Alternatives considered

- **One giant frame.** Rejected: no resume, no incremental verification, and a
  memory spike on both ends.
- **Content-defined chunking (CDC) / rolling hash.** Deferred to C-11: fixed
  chunks are simpler to verify and resume, and deduplication belongs in the
  Infinity store, which already dedupes by whole-image hash.
- **A full Merkle tree with inclusion proofs.** Not needed for whole-body
  transfer; a flat hash list proves the same thing at this level. A tree is the
  right shape if partial-range proofs become a requirement.
