# Performance baselines (Active RPC)

`cargo bench -p active-rpc` (criterion). Numbers are from a Windows 11 /
x86-64 / Rust 1.99 `dev`-profile baseline run used as the regression reference;
re-run on your target and compare ratios rather than absolutes.

The fixture is a four-table Active module (~1.3 KiB encoded) carried with a
capability descriptor, so every number includes a real Infinity payload.

| Benchmark | What it measures | Baseline |
|---|---|---|
| `wire/envelope-encode` | serialize an envelope + module + capability table | ~260 ns |
| `wire/envelope-decode` | validate and decode the same | ~650 ns |
| `transport/in-process` | send + receive without serialization | ~590 ns |
| `transport/shared-memory` | write frame + read frame from the ring | ~1.4 µs |
| `kernel/call-and-run` | minted capability → call → dispatch → promise value | ~7 µs |

## What these numbers mean

- **The wire is not the bottleneck.** Encoding/decoding a kilobyte-scale module
  costs microseconds; a provider round-trip costs more than the bytes.
- **Pipelining is the win that matters.** A dependent chain halves the number of
  provider round-trips (2 → 1 in the tests), which at any realistic latency
  dominates encode/decode cost.
- **In-process is free by construction.** `bytes_written() == 0` for the
  in-process transport; the envelope moves by value.
- **QUIC and the Connect bridge** are correctness-first: they are the interop and
  cross-host paths, not the hot path. Their tests assert payload + capability
  table transfer and malformed-frame rejection, not throughput.

## Regression policy

- A change that makes `envelope-decode` or `kernel/call-and-run` more than 20%
  slower needs a note in this file and an ADR if it is structural.
- Numbers are recorded per release in the release checklist.
