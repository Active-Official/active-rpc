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
- Each accepted frame is **charged before it is stored** (`with_budget`,
  `accept_charged`); a refused charge leaves no state.
- `finish()` requires every chunk, checks the total length and re-verifies the
  body against the plan. A truncated or corrupted body never becomes a valid
  image.
- `BulkProvider` holds state **per object** (what `Provider::invoke` carries);
  attenuation preserves the object, so an object is expected to have one
  principal and a delegated capability shares its slot. `Provider::on_drop`
  releases both the in-progress transfer and an untaken completed body; an
  incomplete transfer expires after 60 s of inactivity and an untaken body after
  10 minutes, both against the kernel clock, and the digest reply outlives the
  bytes. `plan` refuses to start a new transfer for an object whose completed
  body has not been taken, and `finish` is idempotent per object so a lost answer
  can be retried even after `take_body`. `missing` answers a page of 1 024
  indexes with `more` and `remaining`, keeps the transfer alive and never expires
  it. The finish reply carries `body_hash` (raw digest, never a content address)
  and `content`: the canonical hash of the **redacted** image when the body is
  an Infinity image. The transfer context is supplied by
  `BulkProvider::with_context`, one per provider instance.
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
  including one `missing` page per 1 024 chunks for a resume.
- `finish` is the one bulk path that reads the wall clock: the grant is a
  *duration* (`max_wall_ms`), which `Call::now_ms` cannot express, so the
  deadline is anchored at `Instant::now()` and re-checked between chunks and
  before the verification pass. Every other lifetime is measured from the kernel
  clock.
- The per-chunk hash means a receiver verifies each chunk on arrival; the root
  proves the whole set. It is a two-level Merkle shape without the tree.
- Authority stays on the ARP1 envelope: the provider is reached through a
  capability that grants `plan`/`put`/`finish`, and the ingress charge covers the
  chunk bytes, so the module cannot become an ambient file channel.
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
