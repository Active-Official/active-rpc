# Baseline inventory — active-rpc

Recorded: 2026-10-29, maturity program AIM-PROP-2026-10.
Baseline commit: `d8c72373125d76b79582ff456f62a15c1de23b12` (branch `main`).

## Package

| Field | Value |
|---|---|
| Crate | `active-rpc` 2.0.0 |
| Edition / MSRV | 2021 / 1.88 |
| License | MIT OR Apache-2.0 |
| Wire format | ARP1 |
| Default feature | `quic` |
| Dependencies | `active-infinity` 2.1.0, `active-core` 1.4.0, `thiserror`, `blake3`, `getrandom`, `serde_json`; optional `tokio`, `quinn`, `rustls`, `rcgen` |
| Binaries | `active-rpc-peer` |
| Bench | `benches/transport.rs` (criterion) |

## Public surface

Modules: `budget`, `cap`, `channel`, `domain`, `error`, `kernel`, `lane`,
`promise`, `security`, `tool`, `transport`, `value`, `wire`.

Root re-exports: `Budget`, `BudgetMeter`, `CapAttrs`, `CapHandle`, `CapId`,
`CapRecord`, `CapToken`, `ProviderId`, `ToolPolicy`, `Channel`, `ChannelId`,
`Direction`, `Message`, `Error`, `Result`, `Agent`, `Event`, `Metrics`,
`PromiseHandle`, `Provider`, `Lane`, `LaneId`, `PromiseId`, `PromiseState`,
`Arg`, `Call`, `Response`, `Value`, `CapDescriptor`, `Envelope`, `Kind`,
`WireLimits`, `VERSION`, `PROTOCOL_VERSION`, `MODULE_METHODS`.

`Agent` provides mint/attenuate/import/revoke, lanes, channels, send/recv, call,
run, await, resolve/cancel, metrics, events, promise/job counts, lane/channel
lookups, `total_events` (monotonic event count for tails).

## Tests and proof

- 115-test inventory in `docs/hardening/STATUS.md`; suites cover unit,
  integration, property, conformance, concurrency, red-team, API surface, doc
  gate and performance budget.
- Control plane adds 25 engine tests, 4 HTTP tests and a two-launch harness.
- Fuzz targets: `fuzz_arp1_frame`, `fuzz_budget_matrix`,
  `fuzz_capability_lifecycle`, `fuzz_channel_cap_transfer`,
  `fuzz_promise_graph`, `fuzz_tool_http`, `fuzz_tool_mcp`,
  `fuzz_tool_process`, `fuzz_transport_framing`.
- 8 target-specific seed corpora under `fuzz/corpus/`.
- ADRs 0001–0007; specs `wire`, `security`, `performance`; hardening pack,
  signed release records, SBOM/deny/signing tooling.

## Transports and tools

- In-process, TCP, shared-memory ring, QUIC (feature), Connect/gRPC framing.
- MCP stdio/memory transports, allow-listed HTTP tool, sandboxed local process.
- Domain provider with evaluate/why/impact/stats/content_hash and budgets.
- Control plane: dashboard, REST/WS/MCP, 22-step L0–L6 ladder, 20 gauges,
  JSONL/cursor events, read-only mode.

## Facades and registry

`facades/` contains `active-rpc-kernel`, `active-rpc-core`,
`active-rpc-client`, `active-rpc-tools`, `active-rpc-transport`, all 0.1.1 on
crates.io. `active-rpc` 2.0.0 and `active-rpc-cli` 0.1.0 (reserved) are on
crates.io. `REGISTRY.md` maps the family.

## Gaps against AIM-PROP-2026-10

- Capability table is full in every envelope; no delta encoding/negotiation.
- Cancellation is per promise/lane, without an explicit dependency-tree policy.
- No explicit channel/call backpressure credits or flood metrics.
- No authenticated transport identity binding for capability introduction.
- HTTP/2 is available only through the Connect framing bridge, not as a
  first-class ARP1 transport.
- No bulk/carousel chunked body transfer with per-chunk hashes/resume.
- No idempotency keys on mutating domain operations.
- No durable/ephemeral capability persistence policy.
- No `active-rpc-cli` implementation (name reserved only).
- No C ABI/WASM surface for thin polyglot clients.
