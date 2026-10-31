# Performance baselines (Active RPC)

`cargo bench --locked --bench transport` (criterion). Baseline machine:
Windows 11, x86-64, Rust stable, 20 samples, 1 s warm-up and 2 s measurement
per point, on an idle machine (2026-10-27).

Fixtures: an 868-byte `ARP1` envelope carrying a real Active Infinity module,
the in-process queue transport, a 4 MiB shared-memory segment, and a kernel with
one `ModuleProvider` answering `stats`.

## Matrix

| Operation | Result |
|---|---|
| envelope encode | 273 ns (2.96 GiB/s) |
| envelope decode | 703 ns (1.15 GiB/s) |
| in-process transport round trip | 724 ns |
| shared-memory transport round trip | 1.09 µs (637 MiB/s) |
| kernel call + dispatch (`call-and-run`) | 6.63 µs |
| 8 call-and-wait calls (sequential) | 52.9 µs |
| 8 queued calls, one drain (batched) | 55.1 µs |

The two eight-call numbers are total cost, including eight call setups and eight
promise settlements. Round-trip count is the designed difference and is proved
separately: `pipelining_costs_one_round_trip_and_sequential_costs_two` asserts
`round_trips == 1` for a promise-dependent chain and `2` for the sequential
form, and `cross_process_peer_pipelines_in_one_round_trip` proves the same over
a real TCP peer (16 pipelined calls, 1 round trip).

## Sustained-load and hostile-input budgets

`tests/perf_budget.rs` enforces the bounds; numbers are the current pass:

| Test | Bound | Why |
|---|---|---|
| `envelope_decode_is_linear` | 2,000 args ≤ 60× the 100-arg time + 50 ms | no quadratic argument walk |
| `in_process_call_throughput_is_bounded` | 5,000 calls < 15 s | dispatch stays proportional |
| `shared_memory_frames_are_bounded` | 10,000 round trips < 10 s | ring arithmetic is O(frame) |
| `repeated_calls_do_not_grow_rss` (Linux) | < 64 MiB growth over 20,000 calls | promise/meter cleanup |
| `lane_and_channel_churn_does_not_leak_descriptors_or_threads` (Linux) | FD and thread counts do not grow over 2,000 cycles | no hidden per-lane resource |

The hostile battery adds the fail-closed side: a queue storm under a low call
budget (H2.19), nested byte bombs (H2.20), registry ceilings (H2.21), zero
ceilings (H2.23) and a tool payload that exceeds its policy (H2.22) all return a
stable `rpc/*` error before work is materialised. The event log is capped at
`MAX_EVENTS = 16_384` records with exact counters, so a call storm cannot grow
kernel memory without bound.

## Where the time goes

- **Envelope encode/decode is a tight binary walk.** Capability descriptors,
  arguments and payload are length-prefixed; decode refuses counts that exceed
  the buffer before allocating (`WireLimits`).
- **A call is validation plus metering.** `call` checks capability state,
  method grant, read-only policy, path scope, tool policy, and both budgets
  before a promise record exists. That is why one call costs microseconds even
  when the provider does almost nothing.
- **Dispatch batches per provider.** Jobs for one provider run in one batch,
  ordered by promise dependency. The benchmark's batched case is dominated by
  the eight `call` validations, not by transport; over a real transport the
  round-trip count is what matters.
- **Shared memory copies once per direction.** The ring is atomically advanced
  and the payload is copied into the caller's buffer; there is no deserialize
  step on the transport path.

## Regression policy

A change that moves a benchmark by more than 20% on the same machine needs a
note here and a fresh baseline in the same commit. CI compiles the benchmark
binary (`cargo bench --no-run`) and runs `tests/perf_budget.rs`; it does not gate
on cross-machine absolute time. The 32-bit lane runs the same budget tests under
i686, where `usize` arithmetic is the risk.

## Bakeoff (C-7, 2026-10-30)

Host: Intel Xeon E5-1650 v4 @ 3.60 GHz, Windows 10 Pro, 64 GiB RAM,
`rustc 1.99.1`. Criterion, 20 samples, 1 s warm-up, 2 s measurement, otherwise
idle machine. Run the same commands to reproduce:

```text
cargo bench --all-features --bench bakeoff -- "rpc_protocol"
cargo bench --all-features --bench bakeoff -- "rpc_bakeoff"
cargo run --release --example perf_matrix --all-features
python scripts/perf_gate.py perf-matrix.json
```

### Protocol message path: ARP1 versus gRPC

Same logical call (method, one integer argument, 4 KiB payload). The gRPC
adapter uses `prost` plus the five-byte gRPC prefix; the message is built once
and only encoding and prefix/length validation are timed. HTTP/2 framing and
HPACK headers are excluded, so this isolates the call encoding; the transport
benchmarks cover in-process and shared-memory framing, not HTTP/2.

| Operation | ARP1 | gRPC message | Ratio |
|---|---|---|---|
| encode | 723 ns | 1.37 µs | 0.53x (ARP1 faster) |
| decode | 443 ns | 497 ns | 0.89x (ARP1 faster) |

This is not a claim that ARP1 beats gRPC end to end: gRPC carries HTTP/2
headers, trailers and a richer status model that a deployment may need. It is
the message-path share, which is what the envelope controls.

### Envelope throughput

`examples/perf_matrix` (p50):

| Args | Bytes | encode | decode |
|---|---|---|---|
| 1,000 | 10,036 | 7.9 µs | 24.4 µs |
| 4,000 | 40,036 | 28.0 µs | 98.5 µs |

Decode pays for value-tree allocation; encode writes a flat buffer. The 4x
argument growth costs 3.5x encode and 4.0x decode, inside the gate's linearity
ceiling.

### Kernel throughput and pipelining

| Workload | Wall time | Round trips |
|---|---|---|
| 1,000 sequential `echo` calls | 2.58 ms (2.6 µs/call) | 1,000 |
| 4,000 sequential `echo` calls | 11.0 ms (2.8 µs/call) | 4,000 |
| 100 calls, one dependent promise chain | 372 µs | 1 |
| 100 calls, one at a time | 378 µs | 100 |

Wall time is dominated by per-call work in both shapes; the durable claim is the
round-trip count. A dependency chain does the same work in one dispatch and
therefore one batch, which is what removes the per-hop latency of a real
transport.

### The gate

`scripts/perf_gate.py` enforces tail stability (p95 ≤ 4× p50, or 5x for a
1,000-call batch, plus slack for one scheduler hiccup), linear scaling (4k/1k ≤
10x encode, 12x decode, 12x calls) and the encoded-size sanity check. `--baseline
docs/spec/perf-baseline.json` adds an absolute comparison (p50 ≤ 1.6x, p99 ≤
3.0x) for a release machine. CI runs the ratio gate in the `perf-gate` job; the
matrix is uploaded as an artifact.
