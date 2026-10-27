# ADR-0003 — Transport choices

**Status:** accepted (2026-10-27)

## Context

The proposal requires in-process, shared memory, QUIC and a gRPC/Connect bridge,
each able to move a real payload plus a capability table and reject a malformed
frame. Each choice has a cost in dependencies, portability and security surface.

## Decision

1. **In-process**: envelopes move by value, nothing is encoded. This is the fast
   path for a single binary and the reference for "the transport changed nothing
   but the bytes".
2. **TCP**: a 4-byte length prefix and an envelope. Cross-process, portable, and
   the transport the peer binary and the cross-process test use.
3. **Shared memory**: a byte ring behind a `Mutex`. It keeps
   `#![forbid(unsafe_code)]` and still gives a true zero-copy read through
   `with_frame` — the consumer inspects the payload inside the segment under the
   lock instead of copying it out. A `memmap2`-backed cross-process segment is a
   drop-in replacement for the storage strategy; the layout is unchanged.
4. **QUIC**: real QUIC (quinn + rustls) with a self-signed certificate on
   loopback, one bidirectional stream per call. Internet-scale concerns (public
   CA, NAT traversal, load balancing) are out of scope and documented as such.
5. **gRPC/Connect bridge**: unary Connect over HTTP/1.1 carrying the gRPC 5-byte
   message framing. This is dependency-free, testable with `curl`, and the same
   framing works behind an HTTP/2 gRPC server. A full HTTP/2 server is a
   deployment concern, not a protocol one, so it stays out of the crate.

## Consequences

- The default build pulls QUIC's dependency tree; `--no-default-features` keeps
  the other four transports and builds on a bare toolchain.
- Every transport is exercised by the same test shape: payload + capability
  table in, response out, malformed frame rejected with an `rpc/…` code.
- The bridge is an interoperability surface: it validates the same envelope the
  kernel does, so a bridge client cannot reach a code path a native peer cannot.
- A future mmap-backed shared segment and a pooled bridge client are additive.
