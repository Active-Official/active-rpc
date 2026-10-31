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

- The transport is cleartext (h2c) and loopback-only through its single
  constructor. It carries no peer identity, so a capability bound to a peer
  (`ADR-0011`) cannot be introduced over it; a deployment that needs
  authenticated peers uses QUIC mutual TLS. TLS termination for a remote HTTP/2
  listener belongs to the deployment's terminator.
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

## Addendum: size budgets (M-4.3, 2026-10-31)

The transport accepted the `h2` defaults, which are generous: a header list is
bounded by a large default, there is no field-count cap, stream concurrency is
whatever the connection advertises, and each stream could buffer up to the body
ceiling. That is the amplification class the Absolute Max proposal names, so the
budgets are now explicit constants in `transport::http2` and enforced in three
places.

| Budget | Value | Enforced by |
|---|---|---|
| `MAX_HEADER_LIST` | 32 KiB of decoded field bytes (`name + value + 32` per field) | advertised in `SETTINGS_MAX_HEADER_LIST_SIZE`, then re-checked on the decoded request |
| `MAX_HEADER_FIELDS` | 64 | checked on the decoded request; `h2` does not limit the count |
| `MAX_FRAME` | 16 KiB | `SETTINGS_MAX_FRAME_SIZE` on both sides |
| `MAX_CONCURRENT_STREAMS` | 128 | `SETTINGS_MAX_CONCURRENT_STREAMS` |
| `MAX_STREAM_WINDOW` / `MAX_CONNECTION_WINDOW` | 256 KiB / 2 MiB | `SETTINGS_INITIAL_WINDOW_SIZE` and the connection window |
| `MAX_INFLIGHT_BODY` | 128 MiB per connection | per-stream `Reservation` guard; over budget is `429` before buffering |

Why each one exists:

- **Header list.** HPACK is a compression layer: a few bytes on the wire can
  decode to a header list far larger than the frame that carried it. The bound
  belongs on the decoded list, not on the socket, and a peer that ignores the
  advertised setting is still refused by the explicit check.
- **Field count.** A peer can spend the byte budget on a thousand tiny fields,
  which costs the server a thousand `HeaderValue` allocations per request. The
  cap is 64, far above `content-type` plus tracing headers.
- **In-flight body.** 128 streams times a 64 MiB body ceiling is 8 GiB of
  attacker-chosen memory. The connection-wide reservation turns that into a
  `429`. The default leaves room for two maximum-size bodies, so the documented
  per-request ceiling is still reachable; `with_inflight_budget` tightens it per
  deployment.
- **QUIC.** Raw QUIC has no header-compression layer at all (see below), so the
  equivalent bounds are stream count and receive windows:
  `MAX_CONCURRENT_STREAMS = 256`, no unidirectional streams, 1 MiB per stream and
  8 MiB per connection.

**HTTP/3 is out of scope by construction.** ARP1 rides a QUIC bidirectional
stream, one call per stream, with no HTTP/3 framing and therefore no QPACK
dynamic table. The ecosystem's QPACK amplification class does not apply to this
transport; a deployment that terminates HTTP/3 in front of an Active RPC service
owns that layer, and ADR-0023 records why the I/O layer stays on tokio.

Tests: `tests/http2_budget_tests.rs` proves that an oversized header field, an
over-count field list and an over-budget body never reach the provider, that a
refused request leaves the server able to serve the next one, and that
tracing-sized headers and a body under the budget are served.
