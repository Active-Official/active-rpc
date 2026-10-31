# ADR-0013: Bulk (carousel) transfer with per-chunk hashes

- Status: Accepted
- Date: 2026-10-30
- Context: Maturity Program C-6.3 (PROPOSAL §5.7)

## Problem

An ARP1 envelope body is bounded by the transport frame ceiling (64 MiB), and
Active Infinity images routinely exceed it. Raising the ceiling does not solve
the underlying problem: a multi-gigabyte single frame is unverifiable until the
last byte arrives, cannot be resumed after a disconnect, and forces both ends to
hold the whole body in memory at once. A flaky link turns one lost segment into
a restart.

## Decision

A body is transferred as a **plan** plus **self-verifying chunk frames**, both
carried as ordinary transport frames (length-prefixed on TCP/SHM, stream body on
QUIC/HTTP/2).

**Plan** (`ARBL`, version 1): chunk size, total length, chunk count, per-chunk
Blake3 hashes and a root hash over the plan. The root is
`H(domain, version, chunk_size, total, count, chunk_hash[0..n])`, domain
separated from the Infinity content hash and from the chunk hash.

**Chunk** (`ARBC`, version 1): index, offset, length, hash, bytes. A chunk is
refused unless the offset matches the index, the length matches the plan, the
hash matches the bytes *and* the plan's announced hash.

**Receiver rules.**

- A duplicate chunk with identical bytes is accepted (retransmission is
  idempotent); a duplicate with different bytes is refused.
- `missing()` drives the resume request. A receiver reconstructed from the plan
  asks only for the gaps: a reconnect never restarts the body.
- `finish()` requires every chunk, checks the total length and re-verifies the
  root. A truncated or corrupted body never becomes a valid image.
- A configurable ceiling bounds the bytes a receiver will assemble; the default
  is 1 GiB. A plan above it is refused before any allocation.

**Sender rules.** `frames_from(index)` and `frames_for(missing)` emit only the
requested chunks; a body is held once and never re-hashed per retransmission.

## Consequences

- Memory is `O(body)` at the sender (it already has the bytes) and
  `O(received)` at the receiver, bounded by the ceiling. A streaming sender can
  later emit frames from an iterator without changing the wire format.
- The per-chunk hash means a receiver verifies each chunk on arrival; the root
  proves the whole set. It is a two-level Merkle shape without the tree.
- Chunk frames carry no capability. Authority stays on the ARP1 envelope that
  opens the transfer; the bulk module is a codec plus a receiver state machine,
  so it composes with any transport and cannot become an ambient file channel.
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
