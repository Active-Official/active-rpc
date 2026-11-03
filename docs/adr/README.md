# Architecture Decision Records — Active RPC

| ADR | Title |
|-----|-------|
| [0001](0001-purpose.md) | Purpose of Active RPC |
| [0002](0002-deterministic-kernel.md) | A deterministic kernel with transports as adapters |
| [0003](0003-transports.md) | Transport choices: shared memory, QUIC and the Connect bridge |
| [0004](0004-capability-ids.md) | Capability identity, attenuation and lifetime |
| [0005](0005-promises.md) | Promises, batching and what "pipelined" measures |
| [0006](0006-versioning.md) | Versioning and publishing |
| [0007](0007-msrv.md) | Minimum supported Rust version 1.88 |
| [0008](0008-bakeoff-methodology.md) | Public bakeoff methodology and CI regression policy |
| [0009](0009-capability-table-deltas.md) | Negotiated capability-table deltas |
| [0010](0010-durable-capabilities.md) | Durable versus ephemeral capabilities |
| [0011](0011-transport-identity.md) | Transport identity and capability binding |
| [0012](0012-http2-transport.md) | A native HTTP/2 transport for ARP1 |
| [0013](0013-bulk-transfer.md) | Bulk (carousel) transfer with per-chunk hashes |
| [0014](0014-observability-schema.md) | An observability schema that carries no authority |
| [0015](0015-time-bounded-capabilities.md) | Time-bounded capabilities |
| [0016](0016-capability-receipts.md) | Capability receipts |
| [0017](0017-introduction-modules.md) | Peer introduction modules in Active Infinity |
| [0018](0018-replay-packages.md) | Deterministic replay packages |
| [0019](0019-wasm-guest-tools.md) | Fuel-metered WebAssembly guest tools |
| [0020](0020-capability-filtered-topics.md) | Capability-filtered pub/sub topics |
| [0021](0021-durable-receipt-log.md) | Durable receipt log (`ARRL`) |
| [0022](0022-clock-policy.md) | Clock policy: virtual default, wall clock on request |
| [0023](0023-no-io-uring-backend.md) | No io_uring backend for TCP and QUIC I/O |
| [0024](0024-subscriptions-are-not-authority.md) | Subscriptions are not authority |

## Reading order and supersessions

- **Transports:** 0003 is the original story (shared memory, QUIC, and the
  Connect bridge that carried HTTP/2 framing). 0012 is the **native** HTTP/2
  transport and supersedes the bridge as the way to speak HTTP/2; the bridge
  remains as the Connect/gRPC-compatible adapter. Read 0012 for the current
  design, 0003 for why the transports were chosen, and 0023 for the io_uring
  decision.
- **MSRV:** 0007 is the source of truth and supersedes point 4 of 0006. A change
  to the minimum supported Rust version is a change to 0007.
- **Receipts:** 0016 defines the in-memory receipt and the decision it records;
  0021 defines the durable log that carries those receipts off the process.
- Every ADR states one `**Status:**` line naming the date it was accepted. An ADR
  is never rewritten to change a decision: a later ADR supersedes it and says
  so in its status line.
