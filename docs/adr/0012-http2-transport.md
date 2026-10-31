# ADR-0012: A native HTTP/2 transport for ARP1

- Status: Accepted
- Date: 2026-10-30
- Context: Maturity Program C-6.2 (PROPOSAL §5.5)
- Feature: `http2`

## Problem

QUIC is the primary transport and TCP is the fallback, but a large share of
production networks allow only HTTP/2 through an inspecting proxy or a
TLS-terminating gateway. The existing bridge (`transport::connect`) answers that
need with HTTP/1.1 and gRPC framing, one request per connection. It is the right
interoperability surface for a gRPC toolchain, and the wrong hot path for an
agent that issues thousands of calls: no stream multiplexing, one TCP handshake
per call, and an extra five-byte frame that exists only to satisfy gRPC.

## Decision

Add a feature-gated (`http2`) native transport that carries the ARP1 envelope
unchanged:

```text
POST /active.rpc.v1.Agent/Call HTTP/2
content-type: application/arp1

<envelope bytes>
```

- One long-lived connection per client, many concurrent streams
  (`Http2Client::call_many`). HTTP/2's own flow control is the transport-level
  backpressure; the kernel's queue ceiling remains the application-level one.
- The body is the envelope, not a gRPC frame. No second framing layer, no
  trailers, no status mapping table: an `rpc/...` error is an `Error` envelope
  with status `200`, exactly as on TCP and QUIC. A malformed body is a `400`
  with the stable code in the body.
- The capability table rides inside the envelope, as on every transport.
  Nothing about authority depends on headers; the `:path` selects the service,
  it never grants anything.
- `Http2Server::serve` consumes the server and accepts a fixed number of
  connections, mirroring `BridgeServer::serve`. Tests therefore have a
  deterministic shutdown point instead of a background task nobody joins.
- Streams are handled concurrently under a mutex-protected handler. The handler
  is synchronous by design: the kernel is deterministic and single-threaded, and
  a transport must not turn a provider call into an async boundary.

## Consequences

- Restricted networks get multiplexing and one handshake, with the same wire
  semantics as QUIC. A deployment chooses HTTP/3 (QUIC) where UDP is allowed and
  HTTP/2 where it is not; the envelope does not change.
- `h2`, `http` and `bytes` are optional dependencies. The default build stays
  QUIC + TCP + SHM + bridge; `--no-default-features` still builds with no
  transport dependencies at all.
- The server does not terminate TLS. A deployment puts this behind its TLS
  terminator (or a `rustls` acceptor in a future ADR); the transport accepts a
  plain byte stream, which is what keeps it testable on loopback.
- HEAD, GET and other methods are `405`; there is no caching, no content
  negotiation and no redirect following. HTTP/2 here is a frame carrier, not a
  REST surface.

## Alternatives considered

- **Reuse the Connect bridge and add keep-alive.** Rejected: HTTP/1.1
  pipelining is not multiplexing, and a head-of-line blocked response stalls
  every later call.
- **gRPC over h2 (five-byte prefix plus trailers).** Rejected for the native
  path: the prefix is redundant when the endpoint is ours, and trailers buy
  nothing the envelope does not already carry. The bridge keeps that framing for
  interoperability with third-party gRPC clients.
- **WebSocket upgrade.** Rejected: it is another handshake and another framing
  layer for a stream that HTTP/2 already multiplexes.
